package ue

import (
	"fmt"

	"github.com/lvdund/ngap/ies"
	"github.com/reogac/nas"
)

const (
	AUTH_SUCCESS uint8 = iota
	AUTH_MAC_FAILURE
	AUTH_SYNC_FAILURE
)

// HandleNasPdu parse NAS PDU
func HandleNasPdu(msg *ies.DownlinkNASTransport) {
	pdu := msg.NASPDU
	if len(pdu) == 0 {
		fmt.Println("NAS PDU empty")
		return
	}

	// Decode NAS message
	nasCtx := nas.NewNasContext(false)
	var nasMsg nas.NasMessage
	var err error
	if nasMsg, err = nas.Decode(nasCtx, pdu, false); err != nil {
		fmt.Println("NAS decode failed:", err)
		return
	}

	if nasMsg.Gmm != nil {
		switch nasMsg.Gmm.MsgType {
		case nas.AuthenticationRequestMsgType:
			fmt.Println("Received Authentication Request")

		case nas.AuthenticationRejectMsgType:
			fmt.Println("Received Authentication Reject")

		case nas.IdentityRequestMsgType:
			fmt.Println("Received Identity Request")

		case nas.SecurityModeCommandMsgType:
			fmt.Println("Received Security Mode Command")

		case nas.RegistrationAcceptMsgType:
			fmt.Println("Received Registration Accept")
			fmt.Printf("Registration Accept: %+v\n", nasMsg.Gmm.RegistrationAccept)

		case nas.ConfigurationUpdateCommandMsgType:
			fmt.Println("Received Configuration Update Command")

		case nas.DlNasTransportMsgType:
			fmt.Println("Received DL NAS Transport")

		case nas.ServiceAcceptMsgType:
			fmt.Println("Received Service Accept")

		case nas.ServiceRejectMsgType:
			fmt.Println("Received Service Reject")

		case nas.RegistrationRejectMsgType:
			fmt.Println("Received Registration Reject")

		case nas.GmmStatusMsgType:
			fmt.Println("Received Status 5GMM")

		case nas.DeregistrationAcceptFromUeMsgType:
			fmt.Println("Received Deregistration Accept")

		case nas.DeregistrationRequestToUeMsgType:
			fmt.Println("Received Deregistration Request to UE")

		default:
			fmt.Printf("Received unknown NAS message type: 0x%x\n", nasMsg.Gmm.MsgType)
		}
	} else {
		fmt.Println("NAS message has no GMM content")
	}
}
