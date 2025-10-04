package fsm

import (
	"context"
	"fmt"
	"math/rand"
	"emulator/pkg/model"
	"time"
)


type FsmFuzzer struct {
	*Fsm
	*FuzzerOptions
	ctx context.Context
}

type FuzzerOptions struct {
	FuzzMode       bool
	PossibleStates []model.StateType
	PossibleEvents []model.EventType
}

func NewFsmFuzzer(baseFSM *Fsm, opts *FuzzerOptions, ctx context.Context) *FsmFuzzer {
	return &FsmFuzzer{
		Fsm:           baseFSM,
		FuzzerOptions: opts,
		ctx:           ctx,
	}
}

func (ff *FsmFuzzer) AutoRandomEvent(state *State, event *EventData, dur time.Duration) {
	ticker := time.NewTicker(dur)
	defer ticker.Stop()

	for {
		select {
		case <-ff.ctx.Done():
			return
		case <-ticker.C:
			ff.SendEvent(state, event)
		}
	}
}

func (ff *FsmFuzzer) SyncSendEvent(state *State, event *EventData) error {
	var errCh chan error
	if !ff.FuzzMode {
		return ff.Fsm.SyncSendEvent(state, event)
	}
	ff.fuzzSync(state, errCh, true)
	//TODO: return errCh
	return nil
}

func (ff *FsmFuzzer) SendEvent(state *State, event *EventData) chan error {
	if !ff.FuzzMode {
		return ff.Fsm.SendEvent(state, event)
	}
	errCh := make(chan error, 1)
	go func() {
		ff.fuzzSync(state, errCh, false)
	}()
	return errCh
}

func (ff *FsmFuzzer) fuzzSync(state *State, errCh chan error, sync bool) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	randomState := ff.PossibleStates[r.Intn(len(ff.PossibleStates))]
	randomEventType := ff.PossibleEvents[r.Intn(len(ff.PossibleEvents))]

	// Directly manipulate state (unsafe in production—only for fuzzing)
	state.setState(randomState)
	randomEvent := &EventData{evType: randomEventType, evDat: nil}

	fmt.Printf("[Fuzzer] Forcing state: %v, event: %v\n", randomState, randomEventType)

	// Call generic handler (ignores transition rules)
	// ff.handler(state, randomEvent)
	// ff.processNextEvent(state)

	ff.handleEvent(state, randomEvent, errCh, sync)
}
