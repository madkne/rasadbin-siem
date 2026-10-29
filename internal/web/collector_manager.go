package web

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
)

var ErrCollectorNotImplemented = errors.New("collector is not implemented")

type CollectorRunner func(context.Context) error

type CollectorFactory func() (CollectorRunner, error)

type managedCollector struct {
	cancel context.CancelFunc
	done   chan struct{}
}

type CollectorManager struct {
	mu sync.Mutex

	store   *IntegrationStore
	factories map[string]CollectorFactory
	running   map[string]*managedCollector

	ctx    context.Context
	cancel context.CancelFunc
	closed bool
}

func NewCollectorManager(
	parent context.Context,
	store *IntegrationStore,
) *CollectorManager {
	ctx, cancel := context.WithCancel(parent)

	return &CollectorManager{
		store:     store,
		factories: make(map[string]CollectorFactory),
		running:   make(map[string]*managedCollector),
		ctx:       ctx,
		cancel:    cancel,
	}
}

// Register associates an integration ID with its collector factory.
func (m *CollectorManager) Register(
	id string,
	factory CollectorFactory,
) error {
	if id == "" || factory == nil {
		return errors.New("integration ID and factory are required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return errors.New("collector manager is closed")
	}
	if _, exists := m.factories[id]; exists {
		return fmt.Errorf("collector already registered: %s", id)
	}

	m.factories[id] = factory
	return nil
}

// Apply starts or stops a collector to match the latest integration config.
func (m *CollectorManager) Apply(id string) error {
	item, ok := m.store.Get(id)
	if !ok {
		return fmt.Errorf("unknown integration: %s", id)
	}

	if !item.Enabled {
		return m.stop(id)
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return errors.New("collector manager is closed")
	}
	if _, exists := m.running[id]; exists {
		m.mu.Unlock()
		return nil
	}

	factory, registered := m.factories[id]
	if !registered {
		m.mu.Unlock()
		return m.setStatus(id, "failed",
			fmt.Errorf("%w: %s", ErrCollectorNotImplemented, id))
	}
	m.mu.Unlock()

	runner, err := factory()
	if err != nil {
		return m.setStatus(id, "failed", err)
	}
	if runner == nil {
		return m.setStatus(id, "failed",
			errors.New("collector factory returned a nil runner"))
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return errors.New("collector manager is closed")
	}
	// Recheck under the lock in case concurrent updates raced.
	if _, exists := m.running[id]; exists {
		m.mu.Unlock()
		return nil
	}

	ctx, cancel := context.WithCancel(m.ctx)
	entry := &managedCollector{
		cancel: cancel,
		done:   make(chan struct{}),
	}
	m.running[id] = entry
	m.mu.Unlock()

	// Run asynchronously; collectors must return when ctx is cancelled.
	go func() {
		err := runner(ctx)

		m.mu.Lock()
		if m.running[id] == entry {
			delete(m.running, id)
		}
		closed := m.closed
		m.mu.Unlock()

		close(entry.done)

		if err != nil && ctx.Err() == nil && !closed {
			_ = m.setStatus(id, "failed", err)
			slog.Error("collector stopped unexpectedly",
				"integration", id, "error", err)
			return
		}

		if ctx.Err() == nil && !closed {
			// A collector that returns unexpectedly without an error
			// is not considered healthy.
			_ = m.setStatus(id, "failed",
				errors.New("collector exited unexpectedly"))
		}
	}()

	// Initial status is set after registration and before returning.
	if err := m.setStatus(id, "running", nil); err != nil {
		cancel()
		return err
	}

	slog.Info("collector started", "integration", id)
	return nil
}

func (m *CollectorManager) stop(id string) error {
	m.mu.Lock()
	entry := m.running[id]
	m.mu.Unlock()

	if entry != nil {
		entry.cancel()
		<-entry.done
	}

	return m.setStatus(id, "disabled", nil)
}

func (m *CollectorManager) setStatus(
	id string,
	status string,
	cause error,
) error {
	// Implemented by IntegrationStore in integrations.go.
	if err := m.store.SetStatus(id, status); err != nil {
		return err
	}

	if cause != nil {
		slog.Error("collector status changed",
			"integration", id,
			"status", status,
			"error", cause)
	}
	return nil
}

// Reconcile starts enabled integrations on application startup.
func (m *CollectorManager) Reconcile() {
	for _, item := range m.store.List() {
		if !item.Enabled {
			continue
		}
		if err := m.Apply(item.ID); err != nil {
			slog.Error("collector reconciliation failed",
				"integration", item.ID, "error", err)
		}
	}
}

// Close stops every collector and releases manager resources.
func (m *CollectorManager) Close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	entries := make([]*managedCollector, 0, len(m.running))
	for _, entry := range m.running {
		entries = append(entries, entry)
	}
	m.mu.Unlock()

	m.cancel()

	for _, entry := range entries {
		entry.cancel()
	}
	for _, entry := range entries {
		<-entry.done
	}
}