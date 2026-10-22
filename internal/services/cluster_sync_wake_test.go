package services

import (
	"context"
	"testing"
	"time"
)

// 重新注册健康的从节点时，Resume/Wake 必须打断当前 interval 等待。
func TestSyncService_WakeInterruptsDefaultWait(t *testing.T) {
	s := &SyncService{}
	started := make(chan struct{})
	done := make(chan bool, 1)
	go func() {
		close(started)
		done <- s.defaultWaitDelay(context.Background(), time.Hour)
	}()
	<-started
	time.Sleep(20 * time.Millisecond)
	s.Wake()
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("defaultWaitDelay returned false after Wake")
		}
	case <-time.After(time.Second):
		t.Fatal("Wake did not interrupt defaultWaitDelay")
	}
}
