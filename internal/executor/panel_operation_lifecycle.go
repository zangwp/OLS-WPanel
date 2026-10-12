package executor

import (
	"errors"
	"sync"
)

var (
	ErrPanelOperationsBusy   = errors.New("网站任务正在排队或运行，请等待完成后再更新面板")
	ErrPanelOperationsClosed = errors.New("面板正在更新或关闭，暂不接受新的执行任务")
	panelOperations          = &panelOperationLifecycle{}
)

// Admission and the update barrier share this mutex. An empty task/operation
// snapshot can never be followed by a new admitted writer before restart.
type panelOperationLifecycle struct {
	mu       sync.Mutex
	active   int
	blocked  bool
	stopping bool
}

func (l *panelOperationLifecycle) acquire() (func(), error) {
	l.mu.Lock()
	if l.blocked {
		l.mu.Unlock()
		return nil, ErrPanelOperationsClosed
	}
	l.active++
	l.mu.Unlock()
	var once sync.Once
	return func() { once.Do(func() { l.mu.Lock(); l.active--; l.mu.Unlock() }) }, nil
}

func (l *panelOperationLifecycle) beginUpdate() (func(), error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.blocked {
		return nil, ErrPanelOperationsClosed
	}
	if l.active != 0 {
		return nil, ErrPanelOperationsBusy
	}
	l.blocked = true
	var once sync.Once
	return func() { once.Do(func() { l.mu.Lock(); l.blocked = l.stopping; l.mu.Unlock() }) }, nil
}

func (l *panelOperationLifecycle) updateBlocker() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.blocked {
		return ErrPanelOperationsClosed
	}
	if l.active != 0 {
		return ErrPanelOperationsBusy
	}
	return nil
}

func (l *panelOperationLifecycle) stopAdmission() {
	l.mu.Lock()
	l.stopping = true
	l.blocked = true
	l.mu.Unlock()
}

// ClosePanelOperationAdmission is irreversible for normal shutdown. Already
// running operations retain their leases and can finish or roll back.
func ClosePanelOperationAdmission() { panelOperations.stopAdmission() }
