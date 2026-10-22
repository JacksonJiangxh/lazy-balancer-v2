package ownership

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// logf 是包级日志接缝（镜像 services/certjoblog.go certJobLogWarnf
// 先例）：默认落到标准 log（stdout）；ownership 是独立 module 边界（被
// dnsprovider/services 反向依赖，不得回依赖 services），故由
// cmd/server/main.go 装配时注入 services.Logf，使告警进入统一日志级别链。
var logf = func(level, format string, args ...any) { log.Printf(format, args...) }

// SetLogf 装配包级日志函数（main 启动早期调用；nil 忽略）。
func SetLogf(f func(level, format string, args ...any)) {
	if f != nil {
		logf = f
	}
}

const ownershipFileName = "acme_dns_ownership.json"

// staleOwnershipAge is the age beyond which an ownership entry can no longer
// belong to a live issuance: the CA queue caps execution at 60 minutes and the
// deferred cleanup budget is capped at 8 minutes (acme dnsCleanupBudgetMax,
// so anything older is provably abandoned and may be removed by any
// later cleanup without endangering a concurrent challenge.
const staleOwnershipAge = 75 * time.Minute

var fileMu sync.Mutex

// AcquireFileLockForTest exposes the package lock's contention boundary to
// cross-package tests proving callers use the same writer. Production code must
// never call it; the returned release must be called exactly once.
func AcquireFileLockForTest() func() {
	fileMu.Lock()
	return fileMu.Unlock
}

// Record is one owned DNS TXT record. Value and CreatedAt were added later;
// files written by older binaries decode with zero values and are handled as
// legacy entries (see MatchingValue).
//
// Account是创建该条目的凭据摘要（见 AccountDigest）：
// 同一 zone 的 DNS 凭据换成另一账户后，旧条目仍留在文件里，按名称清理若照旧
// 用 record_id 调 provider 删除，新账户会去删「同 ID 的无关记录」（旧账户的
// TXT 在新账户查无此 ID，最多幂等删除；但 ID 在域内被复用时会命中他记录）。
// 旧文件没有该字段 → 空值 = legacy（无法归属），由 DecideRemoval 保守处理。
type Record struct {
	Provider  string    `json:"provider"`
	Zone      string    `json:"zone"`
	FQDN      string    `json:"fqdn"`
	Value     string    `json:"value"`
	RecordID  string    `json:"record_id"`
	Account   string    `json:"account,omitempty"`
	CreatedAt time.Time `json:"created_at,omitempty"`
}

// Stale 报告该条目是否已超出任何在途签发的生命周期（CA 队列 60min + 清理
// 预算 8min 的上界，见 staleOwnershipAge），即已可被任意后续清理回收。
// 零值 CreatedAt（更早版本写入且从未回填）不判 stale：无法证明它已过期，
// 保守按「可能仍在本轮签发中」处理（与 MatchingValue 的既有口径一致）。
func (r Record) Stale(now time.Time) bool {
	return !r.CreatedAt.IsZero() && now.Sub(r.CreatedAt) > staleOwnershipAge
}

// AccountDigest 由凭据派生账户身份（sha256 前 4 字节 = 8 位十六进制），
// 与 dnspod 的 domainIDCacheKey 同源口径：不落凭据明文（所有权文件是明文
// JSON，落盘/集群快照/排障转储都可读），且同一凭据多进程/多实例得到同一值。
func AccountDigest(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:4])
}

// Disposition 是清理方对一条所有权条目的处置结论。
type Disposition int

const (
	// DispositionDelete 表示可以调用 provider 删除该 record_id（条目可归属
	// 当前账户，或是本账户升级前写入的、仍在在途窗口内的 legacy 条目）。
	DispositionDelete Disposition = iota
	// DispositionDrop 表示不能证明条目归属当前账户：只丢弃本地所有权条目，
	// MUST NOT 按 record_id 调 provider 删除（换凭据后 ID 可能指向无关记录）。
	DispositionDrop
)

// DecideRemoval 判定清理方（account 为当前凭据摘要）能否按 record_id 删除该
// 条目。单源实现：dnspod 与 tencent 的 cleanUp 各自维护删除链（底层 SDK/ID
// 类型不同），但账户归属判定 MUST 共用此函数，避免两侧口径漂移。
//
// 规则（保守优先，安全方向一体）：①账户匹配 → 删；②账户明确不同 → 只丢弃；
// ③legacy（Account 空、无法归属）且未陈旧 → 删（升级前本账户写入的在途条目，
// 保持既有清理语义）；④legacy 且已陈旧 → 只丢弃——陈旧条目不可能属于在途
// 签发，而换过凭据后它可能来自旧账户，按 ID 删除有命中无关记录的风险。
// 两侧都无账户信息（调用方未声明身份且条目为 legacy，如测试/内存模式）按 ③
// 的宽松口径处理；条目有账户而调用方未声明身份则归入 ②（无法证明归属）。
func DecideRemoval(record Record, account string, now time.Time) Disposition {
	switch {
	case record.Account != "" && account != "":
		if record.Account == account {
			return DispositionDelete
		}
		return DispositionDrop
	case record.Account == "":
		if record.Stale(now) {
			return DispositionDrop
		}
		return DispositionDelete
	default:
		// record.Account 非空而调用方未声明账户：无法证明归属，只丢弃。
		return DispositionDrop
	}
}

type Store struct {
	path string
}

type state struct {
	Version int      `json:"version"`
	Records []Record `json:"records"`
}

func New(dataDir string) (*Store, error) {
	if dataDir == "" {
		return nil, errors.New("DNS ownership data directory is required")
	}
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("create DNS ownership directory: %w", err)
	}
	return &Store{path: filepath.Join(dataDir, ownershipFileName)}, nil
}

// Replace atomically replaces the ownership file with a validated cluster
// snapshot. It deliberately shares fileMu and the same atomic writer as Store
// mutations so a snapshot apply cannot overwrite a concurrent Add/Remove.
func Replace(dataDir string, data []byte) error {
	// 先取锁再做任何准备工作（解码/建目录）——锁前
	// 的准备会给「Replace 确实共用 fileMu」的并发测试留下假绿窗口：goroutine
	// 还没走到加锁点，固定等待就静默通过，断言变成空断言。锁内解码的代价
	// 可忽略（快照为单文件、签发级频次）。
	fileMu.Lock()
	defer fileMu.Unlock()
	var snapshot state
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return fmt.Errorf("decode DNS ownership snapshot: %w", err)
	}
	if snapshot.Version != 1 || snapshot.Records == nil {
		return errors.New("invalid DNS ownership snapshot")
	}
	store, err := New(dataDir)
	if err != nil {
		return err
	}
	if existing, readErr := os.ReadFile(store.path); readErr == nil && bytes.Equal(existing, data) {
		return nil
	}
	return store.writeAtomic(data)
}

func (s *Store) Add(record Record) error {
	fileMu.Lock()
	defer fileMu.Unlock()
	current, err := s.load()
	if err != nil {
		return err
	}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now()
	}
	current.Records = append(current.Records, record)
	return s.save(current)
}

// Matching returns every ownership entry recorded under the challenge name,
// regardless of account :换凭据后旧账户的条目必须被清理方
// 看到，才能按 ownership.DecideRemoval 判定「丢弃本地条目而非按 ID 删除」。
// 调用方 MUST 在调用 provider 删除前做该归属判定。
func (s *Store) Matching(provider, zone, fqdn string) ([]Record, error) {
	fileMu.Lock()
	defer fileMu.Unlock()
	current, err := s.load()
	if err != nil {
		return nil, err
	}
	matching := make([]Record, 0)
	for _, record := range current.Records {
		if record.Provider == provider && record.Zone == zone && record.FQDN == fqdn {
			matching = append(matching, record)
		}
	}
	return matching, nil
}

// MatchingValue returns the name-matching records that a cleanup for one
// challenge value may remove: the record created with that value, legacy
// entries persisted before value tracking (empty Value, best-effort), and
// provably stale entries. A recent record of another value may belong to a
// live concurrent issuance and is spared. An empty value disables the value
// filter (legacy name-based matching).
func (s *Store) MatchingValue(provider, zone, fqdn, value string) ([]Record, error) {
	if value == "" {
		return s.Matching(provider, zone, fqdn)
	}
	fileMu.Lock()
	defer fileMu.Unlock()
	current, err := s.load()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	matching := make([]Record, 0)
	for _, record := range current.Records {
		if record.Provider != provider || record.Zone != zone || record.FQDN != fqdn {
			continue
		}
		legacy := record.Value == ""
		// 账户维度不参与选择：他账户/legacy 条目必须能被
		// 清理方看到——看不到就只能永久留存（每次清理重读、永不回收），而
		// 归属判定与「只丢弃不删除」的处置在 DecideRemoval。
		stale := record.Stale(now)
		if record.Value == value || legacy || stale {
			matching = append(matching, record)
		}
	}
	return matching, nil
}

// sameRecord 语义相等：Record 结构内联 == 比较含
// time.Time（wall/ext/loc 指针 + monotonic）——从文件读回经 Matching/
// MatchingValue 得到的记录与调用方持有的原值逻辑时间相同，但 == 可能为
// false（JSON 解码丢弃 monotonic、loc 指针不同），Remove 静默 no-op 留下
// 未清理记录。CreatedAt 用 Equal，其余字段逐项比较。
func sameRecord(a, b Record) bool {
	// Account 纳入相等判定：同一 name/value/record_id 但
	// 账户不同的两条记录（换凭据后的历史残留 vs 当前账户条目）必须各自可
	// 独立 Remove，否则丢弃他账户条目会连带删掉本账户的在途条目。
	return a.Provider == b.Provider && a.Zone == b.Zone && a.FQDN == b.FQDN &&
		a.Value == b.Value && a.RecordID == b.RecordID && a.Account == b.Account &&
		a.CreatedAt.Equal(b.CreatedAt)
}

func (s *Store) Remove(removed Record) error {
	fileMu.Lock()
	defer fileMu.Unlock()
	current, err := s.load()
	if err != nil {
		return err
	}
	remaining := make([]Record, 0, len(current.Records))
	for _, record := range current.Records {
		if !sameRecord(record, removed) {
			remaining = append(remaining, record)
		}
	}
	current.Records = remaining
	return s.save(current)
}

func (s *Store) load() (state, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return state{Version: 1}, nil
	}
	if err != nil {
		return state{}, fmt.Errorf("read DNS ownership: %w", err)
	}
	var current state
	decodeErr := json.Unmarshal(data, &current)
	if decodeErr == nil && current.Version != 1 {
		decodeErr = fmt.Errorf("unsupported DNS ownership version %d", current.Version)
	}
	if decodeErr != nil {
		// The ownership file is a best-effort cache: quarantine the bad bytes
		// instead of failing every later Add/Matching/Remove (which would
		// brick all DNS-01 issuance) until manual deletion. The quarantined
		// file stays on disk for inspection; only a failed quarantine (bytes
		// not preserved) keeps returning the error.
		// 文件名原为秒级时间戳，同一秒内二次损坏会被
		// os.Rename 覆盖（POSIX rename 语义）而丢失上一份取证样本——改为
		// 纳秒时间戳 + 冲突探测。
		quarantined := s.quarantinePath()
		if err := os.Rename(s.path, quarantined); err != nil {
			return state{}, fmt.Errorf("quarantine DNS ownership %s: %w", s.path, errors.Join(decodeErr, err))
		}
		logf("warn", "DNS ownership file %s undecodable (%v), quarantined to %s and continued with empty state", s.path, decodeErr, quarantined)
		return state{Version: 1}, nil
	}
	return current, nil
}

// corruptClock 是隔离文件名的时间源（测试接缝：固定时钟下连续两次
// 隔离必须产生两份独立样本）。生产代码不得改写。
var corruptClock = time.Now

// quarantinePath 返回一个未被占用的隔离文件名：纳秒时间戳为基底，冲突时追加
// 递增序号（os.Stat 探测为 best-effort，命中竞态时由 Rename 的覆盖语义兜底，
// 仅为取证样本，不参与业务判定）。
func (s *Store) quarantinePath() string {
	stamp := corruptClock().UnixNano()
	for suffix := 0; ; suffix++ {
		candidate := fmt.Sprintf("%s.corrupt-%d", s.path, stamp)
		if suffix > 0 {
			candidate = fmt.Sprintf("%s.corrupt-%d-%d", s.path, stamp, suffix)
		}
		if _, err := os.Stat(candidate); errors.Is(err, os.ErrNotExist) {
			return candidate
		} else if err != nil {
			// 无法探测（权限等）：交给 Rename 报错，不在此吞掉。
			return candidate
		}
	}
}

func (s *Store) save(current state) error {
	data, err := json.Marshal(current)
	if err != nil {
		return fmt.Errorf("encode DNS ownership: %w", err)
	}
	return s.writeAtomic(data)
}

// writeAtomic writes one complete snapshot. The caller must hold fileMu; the
// fixed temporary path is safe precisely because Store and Replace share it.
func (s *Store) writeAtomic(data []byte) error {
	tmp := s.path + ".tmp"
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("write DNS ownership: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write DNS ownership: %w", errors.Join(err, file.Close()))
	}
	// fsync before the rename so a crash never swaps in an empty or
	// half-written file (same durability contract as certstore.go /
	// cluster_apply.go)
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync DNS ownership: %w", errors.Join(err, file.Close()))
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close DNS ownership: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		removeErr := os.Remove(tmp)
		return fmt.Errorf("replace DNS ownership: %w", errors.Join(err, removeErr))
	}
	if err := syncParentDir(s.path); err != nil {
		return fmt.Errorf("sync DNS ownership directory: %w", err)
	}
	return nil
}

func syncParentDir(path string) error {
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		return errors.Join(err, dir.Close())
	}
	return dir.Close()
}
