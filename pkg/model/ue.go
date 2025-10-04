package model

// TunnelMode indicates how to create a GTP-U tunnel interface in an UE.
type TunnelMode int

const (
	// TunnelDisabled disables the GTP-U tunnel.
	TunnelDisabled TunnelMode = iota
	// TunnelPlain creates a TUN device only.
	TunnelTun
	// TunnelPlain creates a TUN device and a VRF device.
	TunnelVrf
)

type Hplmn struct {
	Mcc string `yaml:"mcc"`
	Mnc string `yaml:"mnc"`
}
type Integrity struct {
	Nia0 bool `yaml:"nia0"`
	Nia1 bool `yaml:"nia1"`
	Nia2 bool `yaml:"nia2"`
	Nia3 bool `yaml:"nia3"`
}
type Ciphering struct {
	Nea0 bool `yaml:"nea0"`
	Nea1 bool `yaml:"nea1"`
	Nea2 bool `yaml:"nea2"`
	Nea3 bool `yaml:"nea3"`
}

// // UE event controller
// type Behaviour string
//
// const (
// 	Register   Behaviour = "register"
// 	Deregister Behaviour = "deregister"
// 	XnHandover     Behaviour = "xnhandover"
// 	N2Handover     Behaviour = "n2handover"
// 	SessionCreate  Behaviour = "sessioncreate"
// 	SessionRelease Behaviour = "sessionrelease"
// 	Idle           Behaviour = "idle"
// 	ServiceRequest Behaviour = "servicerequest"
// )
//
// type State string
// type Event string
//
// const (
// 	Registered   State = "registered"
// 	Deregistered State = "deregistered"
// 	PduActive   State = "pduactive"
// 	PduInactive State = "pduinactive"
//
// 	InitRegister     Event = "initregister"
// 	InitDeregister   Event = "initderegister"
// 	RegisterAccept   Event = "registeraccept"
// 	DeregisterAccept Event = "deregisteraccept"
// 	InitPdu          Event = "initpdu"
// 	AcceptPdu        Event = "acceptpdu"
// 	ReleasePdu       Event = "releasepdu"
// )
