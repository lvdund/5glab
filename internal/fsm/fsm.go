package fsm

import (
	"fmt"
	"maps"
	"emulator/pkg/model"   

	"github.com/alitto/pond/v2"
)

type StateMachine interface {
	SendEvent(*State, *EventData) chan error
	SyncSendEvent(*State, *EventData) error
}

type Transitions map[StateEventTuple]model.StateType
type CallbackFn func(*State, *EventData)
type Callbacks map[model.StateType]CallbackFn

type Fsm struct {
	transitions Transitions
	callbacks   Callbacks
	events      map[model.EventType]bool
	handler     CallbackFn
	done        chan struct{}
	w           pond.Pool
}

type Options struct {
	Transitions           Transitions
	Callbacks             Callbacks
	GenericCallback       CallbackFn
	NonTransitionalEvents []model.EventType
}

func NewFsm(opts Options, w pond.Pool) *Fsm {
	ret := &Fsm{
		transitions: make(map[StateEventTuple]model.StateType),
		callbacks:   make(map[model.StateType]CallbackFn),
		events:      make(map[model.EventType]bool),
		handler:     opts.GenericCallback,
		done:        make(chan struct{}),
		w:           w,
	}

	maps.Copy(ret.callbacks, opts.Callbacks)

	knownStates := make(map[model.StateType]bool)
	knownEvents := make(map[model.EventType]bool)
	for t, s := range opts.Transitions {
		knownStates[t.state] = true
		knownEvents[t.event] = true
		ret.transitions[t] = s
	}

	for s := range knownStates {
		if _, ok := opts.Callbacks[s]; !ok {
			panic("unknown state in callback map")
		}
	}

	// set a generic handler and a list of non-transitional events that will be
	// handled by the handler
	for _, ev := range opts.NonTransitionalEvents {
		if _, ok := knownEvents[ev]; ok {
			panic("Non transional event must not in the transision list")
		} else {
			ret.events[ev] = true
		}
	}

	return ret
}

// Send an event, return a chanel to receive an error reporting if the event is
// invalid on current state
// A caller should never try to retrieve the error if it is within another
// callback. Recursive calling will cause a race condition.
func (fsm *Fsm) SendEvent(state *State, event *EventData) chan error {
	errCh := make(chan error, 1)
	fsm.handleEvent(state, event, errCh, false)
	return errCh
}

// Send an event and wait for it to complete then return error indicating if the
// event was handle.
func (fsm *Fsm) SyncSendEvent(state *State, event *EventData) error {
	errCh := make(chan error, 1)
	fsm.handleEvent(state, event, errCh, true)
	return <-errCh
}

func (fsm *Fsm) processNextEvent(state *State) {
	for state.next != nil {
		next := state.next
		state.next = nil //reset next event for the state
		if _, ok := fsm.events[next.Type()]; ok {
			fsm.handler(state, next)
		} else { //if it is a transitional event
			fsm.transit(state, next, nil)
		}
	}
}

func (fsm *Fsm) handleEvent(state *State, event *EventData, errCh chan error, sync bool) {
	//a state only process one event at a time, so we need to lock it
	//release the state lock after finish handling the event

	//if the event is in the list of non-transitional events
	if _, ok := fsm.events[event.Type()]; ok {
		fn := func() {
			state.slock.Lock()
			fsm.handler(state, event)
			fsm.processNextEvent(state)
			state.slock.Unlock()
		}
		if sync {
			fn()
		} else {
			fsm.w.Submit(fn) //handle the event in a worker pool
		}
		errCh <- nil
	} else { //if it is a transitional event
		fn := func() {
			state.slock.Lock()
			fsm.transit(state, event, errCh)
			fsm.processNextEvent(state)
			state.slock.Unlock() //unlock the state
		}
		if sync {
			fn()
		} else {
			fsm.w.Submit(fn) //handle the event in a worker pool
		}
	}
}

func (fsm *Fsm) transit(state *State, event *EventData, errCh chan error) {
	current := state.CurrentState()
	tuple := StateEventTuple{
		state: current,
		event: event.Type(),
	}

	if nextState, ok := fsm.transitions[tuple]; ok {
		if errCh != nil {
			errCh <- nil
		}
		//execute callback for the event
		curCallback := fsm.callbacks[current]
		nextCallback := fsm.callbacks[nextState]
		if curCallback != nil {
			curCallback(state, event)
		}
		if current != nextState { //state will be changed
			//exectute callback for ExitEvent of the current state
			curCallback(state, event.clone(model.ExitEvent))
			//change to the next state
			state.setState(nextState)
			//execute callback for EtryEvent of the next state
			if nextCallback != nil {
				nextCallback(state, event.clone(model.EntryEvent))
			}
		}
	} else {
		if errCh != nil {
			errCh <- fmt.Errorf("Unknown transition from state %v with event %v", current, event)
		}
	}
}
