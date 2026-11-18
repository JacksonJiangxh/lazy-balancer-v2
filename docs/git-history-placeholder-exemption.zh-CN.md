# Git 历史占位符元数据永久豁免登记

> 登记依据：JJC-20261118-001 D 线（太子裁决成文；此前口径见台账 JJC-20261117-002「收尾核验」行）。
> 登记日期：2026-11-18。性质：**永久豁免**——历史提交元数据不改写，本档为长期有效登记。

## 一、范围（占位符形态的 author/committer 字段）

`git log` 全量身份分布实测（命令见文末复核节）：全仓 3472 个提交中，**3443 个提交**的
author/committer 字段含占位符形态（`{{EMAIL_*}}` 字面量），覆盖 **8 类占位符身份**
（其中裁决时最小发现集为 agent 时代 6 类）：

| 身份形态 | author=占位 | committer=占位 | 提交数 | 来源 |
|---|---|---|---|---|
| `XiaoBao <zhang@xiaobao.cool>` | ✓ | ✓ | 3337 | 上游 fork 承继历史 |
| `root <root@Jackson-Jiang.localdomain>` | ✓ | ✓ | 51 | agent 施工时代（JJC-20261112~16 系列） |
| `JacksonJ <sNZX9…@noreply.cnb.cool>` | ✗（真名） | ✓（`cnb <cnb@cnb.local>`） | 40 | cnb 平台合并落款 |
| `JacksonJ <sNZX9…@noreply.cnb.cool>` | ✗ | ✗ | 22 | 真实身份提交 |
| `lazy-balancer-agent <lazy-balancer-agent@localhost>` | ✗ | ✗ | 7 | 分批提交约定身份（JJC-20261117-002 B1~B7） |
| `CodeBuddy <npc@cnb.cool>` / `<codebuddy@cnb.cool>` | ✓ | ✓ | 7 | 工具代提交 |
| `jxh <jiangxh1993-2@outlook.com>` | ✓ | ✓ | 3 | agent 施工时代 |
| `太史令` / `兵部尚书` / `i.o/x(兵部尚书)` `<npc@cnb.cool>` | ✓ | ✓ | 5 | 角色署名提交 |

另：单字符提交 `2f6746dc`（subject=`a`，author/committer 均 `root <root@Jackson-Jiang.localdomain>`）为同范围既存形态，
一并豁免（台账 JJC-20261117-002 已登记不处置）。

**豁免语义**：上述已发布提交的 author/committer 元数据**保持原样，永久不改写**
（不 rebase、不 filter-branch、不 filter-repo、不 amend、不 force-push 重写）。

## 二、理由（改写已发布历史风险高于收益）

1. **已发布不可静默改写**：main 已推送远程（`origin/main` 同步），改写使全部提交哈希
   从占位符提交点起 cascading 变更——远程强推覆盖、其他克隆/工作树分叉、基于旧哈希的
   引用（台账、档案、PR 记录、`scripts/gate.sh` 第 4 项锚定提交 `0cd475ed`）全部失效；
2. **收益仅为观感**：占位符字段不影响构建、测试、运行与安全（不构成凭据泄露——
   `{{EMAIL_*}}` 是脱敏占位符本体，非真实邮箱）；
3. **风险不对称**：一次误操作的历史改写不可逆（触红线 1「不可逆操作」），观感收益
   不可比——按「改写已发布历史风险高于收益」裁决，永久豁免。

## 三、新内容红线（不变，立即停手）

历史豁免**不放宽新内容口径**，以下任一命中**立即停手上报**（禁止顺手改、禁止提交）：

1. **新提交元数据**：任何新提交的 author/committer 出现占位符形态（`{{EMAIL_*}}`
   字面量、占位符名）。agent 侧提交统一使用既定身份
   `lazy-balancer-agent <lazy-balancer-agent@localhost>`；
2. **新写入文件内容**：任何新写入仓库的文件出现占位符形态字面量
   （`{{NAME_*}}` / `{{EMAIL_*}}` 等）。现状基线：已跟踪文件内容占位符 token
   **0 命中**（`git grep -l '{{[A-Z_a-z]*_[0-9a-z]*}}'` 为空，2026-11-18 实测）。

## 四、复核命令

```bash
# 身份分布（本档第一节表格的数据源）
git log --format='%an <%ae> | %cn <%ce>' | sort | uniq -c | sort -rn
# 新内容红线巡检：文件内容占位符 token（期望 0 命中）
git grep -n '{{[A-Z_a-z]*_[0-9a-z]*}}' -- .
```
