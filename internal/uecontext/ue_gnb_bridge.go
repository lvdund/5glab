package uecontext

type gnbStateResetter interface {
	ResetUeState()
}

var globalGnbResetter gnbStateResetter

func SetGnbResetter(resetter gnbStateResetter) {
	globalGnbResetter = resetter
}

func (ue *UEContext) ResetGnbState() {
	if globalGnbResetter != nil {
		globalGnbResetter.ResetUeState()
	}
}