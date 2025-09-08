package uecontext
/*
import (
	"fmt"

	"github.com/reogac/nas"
)

// Authentication result constants
const (
	AUTH_SUCCESS     = 0
	AUTH_MAC_FAILURE = 1
	AUTH_SYNC_FAILURE = 2
)

// UEContext định nghĩa trạng thái UE
type UEContext struct {
	SUPI string
	PLMN string

	RanUeNgapId int
	AmfUeNgapId int

	Snssai []byte

	MsgFromGnbChan chan []byte
	MsgToGnbChan   chan []byte

	// Authentication
	AuthCtx *AuthContext
	AuthKey []byte
	AuthOpc []byte

	MCC string
	MNC string
}

// Handle NAS bytes từ gNB

func (ue *UEContext) handleNasMsg(nasBytes []byte) {
	if len(nasBytes) == 0 {
		fmt.Println("NAS message is empty")
		return
	}

	nasCtx := nas.NewNasContext(false)

	nasMsg, err := nas.Decode(nasCtx, nasBytes, false)
	if err != nil {
		fmt.Println("Decode NAS message failed:", err)
		return
	}

	ue.handleNasGmm(&nasMsg)
}

// Xử lý các message GMM trong NAS
func (ue *UEContext) handleNasGmm(nasMsg *nas.NasMessage) {
	gmm := nasMsg.Gmm
	if gmm == nil {
		fmt.Println("NAS message has no GMM content")
		return
	}

	switch gmm.MsgType {
	case nas.AuthenticationRequestMsgType:
		fmt.Println("Received Authentication Request")
		ue.handleAuthenticationRequest(gmm.AuthenticationRequest)

	case nas.AuthenticationRejectMsgType:
		fmt.Println("Received Authentication Reject")
		// Xử lý authentication reject nếu cần

	case nas.IdentityRequestMsgType:
		fmt.Println("Received Identity Request")
		// Xử lý Identity Request

	case nas.SecurityModeCommandMsgType:
		fmt.Println("Received Security Mode Command")
		// Xử lý Security Mode Command

	case nas.RegistrationAcceptMsgType:
		fmt.Println("Received Registration Accept")
		// Xử lý Registration Accept

	default:
		fmt.Printf("Received unknown NAS GMM message type: 0x%x\n", gmm.MsgType)
	}
}

// Xử lý Authentication Request
func (ue *UEContext) handleAuthenticationRequest(msg *nas.AuthenticationRequest) {
	if msg == nil {
		fmt.Println("Authentication Request is nil")
		return
	}

	if len(msg.AuthenticationParameterRand) == 0 || len(msg.AuthenticationParameterAutn) == 0 {
		fmt.Println("RAND or AUTN missing in Authentication Request")
		return
	}

	ue.AuthCtx.rand = msg.AuthenticationParameterRand
	autn := msg.AuthenticationParameterAutn
	abba := msg.Abba

	// Tính RES* và lấy errCode
	errCode, resStar := ue.AuthCtx.ProcessAuthenticationInfo(autn, abba)

	var response nas.GmmMessage
	switch errCode {
	case AUTH_SUCCESS:
		fmt.Println("Authentication success, sending Authentication Response")
		resp := &nas.AuthenticationResponse{
			AuthenticationResponseParameter: resStar,
		}
		resp.SetSecurityHeader(nas.NasSecNone)
		response = resp

	case AUTH_MAC_FAILURE:
		fmt.Println("Authentication failed: MAC failure")
		resp := &nas.AuthenticationFailure{
			GmmCause: nas.Cause5GMMMACFailure,
		}
		resp.SetSecurityHeader(nas.NasSecNone)
		response = resp

	case AUTH_SYNC_FAILURE:
		fmt.Println("Authentication failed: Sync failure")
		resp := &nas.AuthenticationFailure{
			GmmCause:                       nas.Cause5GMMSynchFailure,
			AuthenticationFailureParameter: resStar,
		}
		resp.SetSecurityHeader(nas.NasSecNone)
		response = resp
	}

	// Encode NAS message đúng signature (*NasContext, nas.GmmMessage, bool)
	responsePdu, _ := nas.EncodeMm(nas.NewNasContext(false), response, false)
	ue.MsgToGnbChan <- responsePdu
	fmt.Println("Sent Authentication Response/Failure")
}
*/