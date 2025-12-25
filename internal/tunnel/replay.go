package tunnel

import "sync"

// AntiReplay implements a sliding window for sequence validation.
type AntiReplay struct {
	mu      sync.Mutex
	highest uint64
	window  uint64
}

func NewAntiReplay(window uint64) *AntiReplay {
	return &AntiReplay{window: window}
}

func (ar *AntiReplay) Check(seq uint64) bool {
	ar.mu.Lock()
	defer ar.mu.Unlock()

	if seq > ar.highest {
		shift := seq - ar.highest
		if shift >= 64 {
			ar.window = 1
		} else {
			ar.window = (ar.window << shift) | 1
		}
		ar.highest = seq
		return true
	}

	offset := ar.highest - seq
	if offset >= 64 {
		return false
	}
	mask := uint64(1) << offset
	if ar.window&mask != 0 {
		return false
	}
	ar.window |= mask
	return true
}
