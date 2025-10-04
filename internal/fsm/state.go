package fsm

import (
	"emulator/pkg/model"
	"sync"
	"unsafe"
)

type State struct {
	current model.StateType
	next    *EventData
	slock   sync.Mutex //for locking an event handling
	mutex   sync.RWMutex
	info    unsafe.Pointer
}

func NewState[T any](i model.StateType, info *T) *State {
	state := &State{
		current: i,
	}
	if info != nil {
		state.info = unsafe.Pointer(info)
	}
	return state
}

func GetStateInfo[T any](state *State) *T {
	if state.info == nil {
		return nil
	}
	return (*T)(state.info)
}

func (s *State) setState(now model.StateType) {
	s.mutex.Lock()
	s.current = now
	s.mutex.Unlock()
}
func (s *State) ForceSetState(now model.StateType) {
	s.mutex.Lock()
	s.current = now
	s.mutex.Unlock()
}

func (s *State) CurrentState() model.StateType {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.current
}

func (s *State) SetNextEvent(event *EventData) {
	s.next = event
}

type StateEventTuple struct {
	state model.StateType
	event model.EventType
}

func Tuple(state model.StateType, event model.EventType) (tuple StateEventTuple) {
	tuple.event = event
	tuple.state = state
	return
}
