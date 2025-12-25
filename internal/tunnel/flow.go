package tunnel

import (
	"net"
	"sync"
	"time"
)

// Flow represents one UDP mapping.
type Flow struct {
	ID        uint32
	PeerAddr  *net.UDPAddr
	Backend   *net.UDPConn
	UpdatedAt time.Time
}

// FlowTable tracks flows keyed by identifier.
type FlowTable struct {
	mu    sync.Mutex
	table map[uint32]*Flow
	next  uint32
}

func NewFlowTable() *FlowTable {
	return &FlowTable{table: make(map[uint32]*Flow), next: 1}
}

func (ft *FlowTable) Get(id uint32) (*Flow, bool) {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	f, ok := ft.table[id]
	return f, ok
}

func (ft *FlowTable) Add(addr *net.UDPAddr, backend *net.UDPConn, preferredID uint32) *Flow {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	id := preferredID
	if id == 0 {
		id = ft.next
		ft.next++
	} else if id >= ft.next {
		ft.next = id + 1
	}
	f := &Flow{ID: id, PeerAddr: addr, Backend: backend, UpdatedAt: time.Now()}
	ft.table[id] = f
	return f
}

func (ft *FlowTable) Touch(id uint32) {
	ft.mu.Lock()
	if f, ok := ft.table[id]; ok {
		f.UpdatedAt = time.Now()
	}
	ft.mu.Unlock()
}

func (ft *FlowTable) Remove(id uint32) {
	ft.mu.Lock()
	if f, ok := ft.table[id]; ok {
		if f.Backend != nil {
			_ = f.Backend.Close()
		}
		delete(ft.table, id)
	}
	ft.mu.Unlock()
}

func (ft *FlowTable) Cleanup(maxIdle time.Duration) {
	ft.mu.Lock()
	for id, f := range ft.table {
		if time.Since(f.UpdatedAt) > maxIdle {
			if f.Backend != nil {
				_ = f.Backend.Close()
			}
			delete(ft.table, id)
		}
	}
	ft.mu.Unlock()
}
