package store

import (
	"errors"
	"sync"
	"time"

	"github.com/vpn-platform/vpsserver/vpn/internal/modules/vps/aero/domain"
)

var ErrNotFound = errors.New("not found")

type Store interface {
	CreateTask(t *domain.DeployTask) (uint64, error)
	GetTask(id uint64) (*domain.DeployTask, error)
	ListTasks() ([]domain.DeployTask, error)
	AppendLog(id uint64, line string) error
	UpdateProgress(id uint64, stage string, progress int, steps []domain.DeployStep) error
	Finish(id uint64, status, errMsg string) error
	DeleteTask(id uint64) error
	DeleteByStatus(status string) (int, error)
}

type MemoryStore struct {
	mu     sync.RWMutex
	tasks  map[uint64]*domain.DeployTask
	next   uint64
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{tasks: make(map[uint64]*domain.DeployTask)}
}

func copyTask(t *domain.DeployTask) domain.DeployTask {
	cp := *t
	cp.Logs = append([]string{}, t.Logs...)
	cp.Steps = append([]domain.DeployStep{}, t.Steps...)
	return cp
}

func (m *MemoryStore) CreateTask(t *domain.DeployTask) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.next++
	t.ID = m.next
	t.CreatedAt = time.Now()
	if t.Status == "" {
		t.Status = "pending"
	}
	if t.Logs == nil {
		t.Logs = []string{}
	}
	if t.Steps == nil {
		t.Steps = []domain.DeployStep{}
	}
	m.tasks[t.ID] = t
	return t.ID, nil
}

func (m *MemoryStore) GetTask(id uint64) (*domain.DeployTask, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.tasks[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := copyTask(t)
	return &cp, nil
}

func (m *MemoryStore) ListTasks() ([]domain.DeployTask, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]domain.DeployTask, 0, len(m.tasks))
	for _, t := range m.tasks {
		out = append(out, copyTask(t))
	}
	return out, nil
}

func (m *MemoryStore) AppendLog(id uint64, line string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tasks[id]
	if !ok {
		return ErrNotFound
	}
	t.Logs = append(t.Logs, time.Now().Format("15:04:05.000")+"  "+line)
	if t.Status == "pending" {
		t.Status = "running"
	}
	return nil
}

func (m *MemoryStore) UpdateProgress(id uint64, stage string, progress int, steps []domain.DeployStep) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tasks[id]
	if !ok {
		return ErrNotFound
	}
	if stage != "" {
		t.Stage = stage
	}
	if progress >= 0 {
		t.Progress = progress
	}
	if steps != nil {
		t.Steps = append([]domain.DeployStep{}, steps...)
	}
	if t.Status == "pending" {
		t.Status = "running"
	}
	return nil
}

func (m *MemoryStore) Finish(id uint64, status, errMsg string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tasks[id]
	if !ok {
		return ErrNotFound
	}
	t.Status = status
	t.Error = errMsg
	if status == "success" {
		t.Progress = 100
		t.Stage = "完成"
	}
	now := time.Now()
	t.FinishedAt = &now
	return nil
}

func (m *MemoryStore) DeleteTask(id uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tasks[id]
	if !ok {
		return ErrNotFound
	}
	if t.Status == "success" {
		return errors.New("success tasks retained for audit")
	}
	if t.Status == "running" || t.Status == "pending" {
		return errors.New("cannot delete running task")
	}
	delete(m.tasks, id)
	return nil
}

func (m *MemoryStore) DeleteByStatus(status string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for id, t := range m.tasks {
		if t.Status == status {
			delete(m.tasks, id)
			n++
		}
	}
	return n, nil
}
