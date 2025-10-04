package fsm

import (
	"emulator/pkg/model"
	"unsafe"
)

type EventData struct {
	evType model.EventType
	evDat  unsafe.Pointer
}

func NewEmptyEventData(evType model.EventType) *EventData {
	return &EventData{
		evType: evType,
		evDat:  nil,
	}
}

func NewEventData[T any](evType model.EventType, value *T) *EventData {
	ev := &EventData{
		evType: evType,
	}
	if value != nil {
		ev.evDat = unsafe.Pointer(value)
	}
	return ev
}

func (e *EventData) Type() model.EventType {
	return e.evType
}

func GetEventData[T any](e *EventData) *T {
	if e.evDat == nil {
		return nil
	}
	return (*T)(e.evDat)
}

// clone with new event type
func (e *EventData) clone(evType model.EventType) *EventData {
	return &EventData{
		evType: evType,
		evDat:  e.evDat,
	}
}
