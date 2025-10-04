package model

type StateType string
type EventType string

const (
	EntryEvent EventType = "Entry Event"
	ExitEvent  EventType = "Exit Event"
)

// State
const (
	NULL StateType = "NULL State"
	IDLE StateType = "Idle State"

	// UE State 5GMM
	Deregistered            StateType = "Deregisterd State"
	DeregistrationInitiated StateType = "DeregistrationInitiated State"
	AuthenticationInitiated StateType = "AuthenticationInitiated State"
	RegisteredInitiated     StateType = "RegisteredInitiated State"
	Registered              StateType = "Registered State"

	// UE State 5GSM
	PDUSessionInactive        StateType = "PDUSessionInactive State"
	PDUSessionActivePending   StateType = "PDUSessionActivePending State"
	PDUSessionInactivePending StateType = "PDUSessionInactivePending State"
	PDUSessionActive          StateType = "PDUSessionActive State"
	PDUModificationPending    StateType = "PDUModificationPending State"
)

// Event
const (
	Enable EventType = "Enable Event"

	// 5GMM Event
	GmmMessageEvent                   EventType = "GmmMessageEvent Event"
	InitRegistrationRequestEvent      EventType = "InitRegistrationRequestEvent Event"
	RegistrationRejectEvent           EventType = "RegistrationRejectEvent Event"
	AuthFailEvent                     EventType = "AuthFailEvent Event"
	SecurityModeFailEvent             EventType = "SecurityModeFailEvent Event"
	RegistrationAcceptEvent           EventType = "RegistrationAcceptEvent Event"
	InitDeregistrationRequestEvent    EventType = "InitDeregistrationRequestEvent Event"
	DeregistrationAcceptEvent         EventType = "DeregistrationAcceptEvent Event"
	NetworkDeregistrationRequestEvent EventType = "NetworkDeregistrationRequestEvent Event"

	MissingInfo EventType = "MissingInfo Event"

	// timer event
	T3502Event EventType = "t3502Event Event"
	T3510Event EventType = "t3510Event Event"
	T3511Event EventType = "t3511Event Event"

	// 5GSM Event
	InitPduSessionEstablishmentRequestEvent EventType = "InitPduSessionEstablishmentRequestEvent Event"
	EstablishmentReject                     EventType = "EstablishmentReject Event"
	EstablishmentAccept                     EventType = "EstablishmentAccept Event"
	ReleaseRequest                          EventType = "ReleaseRequest Event"
	ReleaseCommand                          EventType = "ReleaseCommand Event"
	ModificationRequest                     EventType = "ModificationRequest Event"
	ModificationCommand                     EventType = "ModificationCommand Event"
	ModificationReject                      EventType = "ModificationReject Event"
	ModificationComplete                    EventType = "ModificationComplete Event"

	// trigger command - remote event
	NullInit           EventType = "NullInit Event"
	IdleInit           EventType = "IdleInit Event"
	RegisterInit       EventType = "RegisterInit Event"
	DeregistraterInit  EventType = "DeregistraterInit Event"
	ServiceRequestInit EventType = "ServiceRequestInit Event"
	PduSessionInit     EventType = "PduSessionInit Event"
	DestroyPduSession  EventType = "DestroyPduSession Event"
	XnHandover         EventType = "XnHandover Event"
	N2Handover         EventType = "N2Handover Event"
	Terminate          EventType = "ue Event" // kill ue
	Kill               EventType = "ue Event" // force kill ue
)
