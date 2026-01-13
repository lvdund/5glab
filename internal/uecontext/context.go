package uecontext

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"emulator/internal/uecontext/sec"
	"github.com/reogac/nas"
)

const (
	PDUSessionInactive = 0
	PDUSessionActive   = 1
)

const (
	InitPduSessionEstablishmentRequestEvent = 100
)

type SecurityContext struct {
	K        []byte
	OPC      []byte
	SQN      uint64
	NASCount uint32
}

type UEContext struct {
	SUPI           string
	PLMN           string
	RanUeNgapId    int
	AmfUeNgapId    int
	Snssai         []byte
	MsgFromGnbChan chan []byte
	MsgToGnbChan   chan []byte
	AuthCtx        *AuthContext
	AuthKey        string
	AuthOpc        string
	AuthOp         string
	MCC            string
	MNC            string
	nasPdu         []byte
	sessions       [16]*PduSession
	UplinkNASChan  chan []byte
	secCtx         *sec.SecurityContext
}

type PduSession struct {
	id    int
	state int
}

func (p *PduSession) SendEventSm(event any) {
	fmt.Println("[PDU] SendEventSm:", event)
}

func NewUEContext(supi, plmn string, ranUeNgapId int, msgFromGnbChan, msgToGnbChan chan []byte) *UEContext {
	ue := &UEContext{
		SUPI:           supi,
		PLMN:           plmn,
		RanUeNgapId:    ranUeNgapId,
		AmfUeNgapId:    0,
		Snssai:         []byte{0x01, 0x01, 0x02, 0x03},
		MsgFromGnbChan: msgFromGnbChan,
		MsgToGnbChan:   msgToGnbChan,
		AuthKey:        "8baf473f2f8fd09487cccbd7097c6862",
		AuthOp:         "8e27b6af0e692e750f32667a3b14605d",
		MCC:            plmn[:3],
		MNC:            plmn[3:],
	}

	op, _ := hex.DecodeString(ue.AuthOp)
	key, _ := hex.DecodeString(ue.AuthKey)

	milenage, _ := sec.NewMilenage(key, op, true)
	ue.AuthCtx = &AuthContext{
		supi:     supi,
		snn:      []byte(plmn),
		amf:      []byte{0x80, 0x00},
		milenage: milenage,
		sqn:      sec.Sqn{},
		rand:     make([]byte, 16),
	}
	ue.secCtx = nil

	return ue
}

func (ue *UEContext) getNasContext() *nas.NasContext {
	if ue.secCtx == nil {
		return nil
	}
	return ue.secCtx.NasContext(true)
}

func (ue *UEContext) HandlerNasMsg() {
	timeout := 20 * time.Second
	for {
		select {
		case msg := <-ue.MsgFromGnbChan:
			fmt.Println("[UE] Received NAS from gNB, len:", len(msg))
			ue.handleNasMsg(msg)
		case <-time.After(timeout):
			fmt.Println("[UE] Timeout waiting for NAS message from gNB, continue...")
		}
	}
}

func (ue *UEContext) handleNasMsg(nasBytes []byte) {
	fmt.Printf("[UE] Handling raw NAS message: %x (len: %d)\n", nasBytes, len(nasBytes))
	if len(nasBytes) < 2 {
		fmt.Println("NAS message too short")
		return
	}

	secHeaderType := nasBytes[1] & 0x0F
	isPlain := secHeaderType == nas.NasSecNone

	var nasCtx *nas.NasContext
	if !isPlain {
		nasCtx = ue.getNasContext()
		if nasCtx == nil {
			fmt.Println("[UE] Protected NAS but NAS context is nil; decoding as plain")
			isPlain = true
		}
	}

	nasMsg, err := nas.Decode(nasCtx, nasBytes, isPlain)
	if err != nil {
		fmt.Println("Decode NAS message failed:", err)
		ue.handleDlNasTransportRaw(nasBytes, secHeaderType)
		return
	}

	if nasMsg.Gmm != nil {
		fmt.Printf("[UE] NAS GMM Message Type: 0x%02x\n", nasMsg.Gmm.MsgType)
	}

	if nasMsg.Gmm != nil && (nasMsg.Gmm.MsgType == 0x67 || nasMsg.Gmm.MsgType == nas.DlNasTransportMsgType) {
		fmt.Println("[UE] Detected DL NAS Transport")
		ue.handleDlNasTransportRaw(nasBytes, secHeaderType)
		return
	}

	ue.handleNasGmm(&nasMsg, secHeaderType)
}

func (ue *UEContext) handleNasGmm(nasMsg *nas.NasMessage, secHeaderType uint8) {
	gmm := nasMsg.Gmm
	if gmm == nil {
		fmt.Println("NAS message has no GMM content")
		return
	}

	switch gmm.MsgType {
	case nas.AuthenticationRequestMsgType:
		fmt.Println("Received Authentication Request")
		ue.handleAuthenticationRequest(gmm.AuthenticationRequest)

	case nas.IdentityRequestMsgType:
		fmt.Println("Received Identity Request")
		ue.handleIdentityRequest(gmm.IdentityRequest)

	case nas.SecurityModeCommandMsgType:
		fmt.Println("Received Security Mode Command")
		ue.handleSecurityModeCommand(gmm.SecurityModeCommand)

	case nas.RegistrationAcceptMsgType:
		fmt.Println("Received Registration Accept")
		ue.handleRegistrationAccept(gmm.RegistrationAccept)

	case nas.ConfigurationUpdateCommandMsgType:
		fmt.Println("Received Configuration Update Command")
		ue.handleConfigurationUpdateCommand(gmm.ConfigurationUpdateCommand)

	default:
		fmt.Printf("Received unknown NAS GMM message type: 0x%x\n", gmm.MsgType)
	}
}

func (ue *UEContext) handleConfigurationUpdateCommand(msg *nas.ConfigurationUpdateCommand) {
	if msg == nil {
		fmt.Println("[UE] Configuration Update Command is nil")
		return
	}

	fmt.Println("[UE] Processing Configuration Update Command...")

	if msg.Guti != nil {
		fmt.Println("[UE] Received new GUTI from network")
	}
	if msg.TaiList != nil {
		fmt.Println("[UE] Received TAI list from network")
	}
	if msg.ServiceAreaList != nil {
		fmt.Println("[UE] Received Service Area list from network")
	}

	response := &nas.ConfigurationUpdateComplete{}

	nasCtx := ue.getNasContext()
	if nasCtx == nil {
		fmt.Println("[UE] Warning: NAS context nil, sending plain ConfigurationUpdateComplete")
		response.SetSecurityHeader(nas.NasSecNone)
		buf, err := nas.EncodeMm(nil, response, true)
		if err != nil {
			fmt.Println("[UE] Encode ConfigurationUpdateComplete (plain) failed:", err)
			return
		}
		ue.MsgToGnbChan <- buf
		fmt.Println("[UE] Sent Configuration Update Complete (PLAIN)")
		return
	}

	response.SetSecurityHeader(nas.NasSecBoth)
	buf, err := nas.EncodeMm(nasCtx, response, false)
	if err != nil {
		fmt.Println("[UE] Encode ConfigurationUpdateComplete failed:", err)
		return
	}

	ue.MsgToGnbChan <- buf
	fmt.Println("[UE] ===== Sent Configuration Update Complete (SECURED) =====")
	fmt.Println("[UE] ===== UE FULLY REGISTERED AND CONFIGURED =====")
}

func (ue *UEContext) handleIdentityRequest(msg *nas.IdentityRequest) {
	if msg == nil {
		fmt.Println("Identity Request is nil")
		return
	}

	plmn := nas.PlmnId{}
	if err := plmn.Parse(ue.MCC + ue.MNC); err != nil {
		fmt.Println("IdentityResponse: parse PLMN failed:", err)
		return
	}

	msin := extractMSIN(ue.SUPI)
	msinBytes, err := nas.ParseMsin(msin)
	if err != nil {
		fmt.Println("IdentityResponse: parse MSIN failed:", err)
		return
	}

	supiImsi := &nas.SupiImsi{
		PlmnId:                 plmn,
		ProtectionScheme:       nas.ProtectionSchemeNullScheme,
		HomeNetworkPublicKeyId: 0,
		SchemeOutput:           msinBytes,
	}
	suci := &nas.Suci{Content: supiImsi}

	resp := &nas.IdentityResponse{
		MobileIdentity: nas.MobileIdentity{
			Id: suci,
		},
	}
	resp.SetSecurityHeader(nas.NasSecNone)

	buf, encErr := nas.EncodeMm(nil, resp, true)
	if encErr == nil {
		ue.MsgToGnbChan <- buf
		fmt.Println("Sent Identity Response (Plain NAS)")
		return
	}
	fmt.Println("Encode IdentityResponse failed:", encErr)
}

func (ue *UEContext) handleAuthenticationRequest(msg *nas.AuthenticationRequest) {
	if msg == nil {
		fmt.Println("[UE] Authentication Request is nil")
		return
	}

	if len(msg.AuthenticationParameterRand) == 0 || len(msg.AuthenticationParameterAutn) == 0 {
		fmt.Println("[UE] RAND or AUTN missing in Authentication Request")
		return
	}

	ue.AuthCtx.rand = msg.AuthenticationParameterRand
	autn := msg.AuthenticationParameterAutn
	abba := msg.Abba

	fmt.Printf("[UE] Received AUTN: %x\n", autn)
	fmt.Printf("[UE] Stored RAND: %x\n", ue.AuthCtx.rand)

	errCode, resStar := ue.AuthCtx.ProcessAuthenticationInfo(autn, abba)
	if errCode != AUTH_SUCCESS {
		fmt.Println("[UE] Authentication failed, cannot compute RES*")
		return
	}

	fmt.Printf("[DEBUG] Computed RES*: %x\n", resStar)
	fmt.Printf("[DEBUG] UE SQN (decoded): %x\n", ue.AuthCtx.sqn)
	fmt.Printf("[DEBUG] Computed KAMF: %x\n", ue.AuthCtx.kamf)

	fmt.Println("==========================[UE] Authentication success =========================")

	if ue.AuthCtx != nil && len(ue.AuthCtx.kamf) > 0 {
		ue.secCtx = sec.NewSecurityContext(&ue.AuthCtx.ngKsi, ue.AuthCtx.kamf, false)
		fmt.Printf("[UE] SecurityCtx created with KAMF: %x\n", ue.AuthCtx.kamf)
	} else {
		fmt.Println("[UE] Warning: no KAMF available after authentication")
	}

	msgResp := &nas.AuthenticationResponse{
		AuthenticationResponseParameter: resStar,
	}
	msgResp.SetSecurityHeader(nas.NasSecNone)

	responsePdu, err := nas.EncodeMm(nil, msgResp, true)
	if err != nil {
		fmt.Println("[UE] Encode Authentication Response failed:", err)
		return
	}
	fmt.Printf("[UE] Authentication Response PDU: %x\n", responsePdu)

	ue.MsgToGnbChan <- responsePdu
	fmt.Println("[UE] Sent Authentication Response (plain NAS)")
}

func (ue *UEContext) TriggerInitRegistration() error {
	if len(ue.Snssai) == 0 {
		ue.Snssai = []byte{0x01, 0x01, 0x02, 0x03}
	}

	ueSecCap := &nas.UeSecurityCapability{}
	ueSecCap.SetEA(0, true)
	ueSecCap.SetEA(1, true)
	ueSecCap.SetEA(2, true)
	ueSecCap.SetIA(0, true)
	ueSecCap.SetIA(1, true)
	ueSecCap.SetIA(2, true)

	suci := new(nas.SupiImsi)
	suci.Parse([]string{"208", "93", "0000", "0", "1", "0000000001"})

	msg := &nas.RegistrationRequest{
		UeSecurityCapability: ueSecCap,
	}
	msg.RegistrationType = nas.NewRegistrationType(true, nas.RegistrationType5GSInitialRegistration)

	msg.MobileIdentity = nas.MobileIdentity{
		Id: &nas.Suci{Content: suci},
	}
	msg.Ngksi = nas.KeySetIdentifier{Tsc: 1, Id: 0}

	var gmmCap [13]byte
	gmmCap[0] = 0x07
	msg.GmmCapability = new(nas.GmmCapability)
	msg.GmmCapability.Bytes = gmmCap[:]

	msg.RequestedNssai = &nas.Nssai{
		List: []nas.SNssai{{
			Sst: 0x01,
			Sd:  []byte{0x01, 0x02, 0x03},
		}},
	}

	msg.SetSecurityHeader(nas.NasSecNone)

	buf, err := nas.EncodeMm(nil, msg, true)
	if err != nil {
		fmt.Println("Failed to encode RegistrationRequest:", err)
		return err
	}

	ue.nasPdu = make([]byte, len(buf))
	copy(ue.nasPdu, buf)

	ue.MsgToGnbChan <- buf

	fmt.Printf("NAS RegistrationRequest sent: PLMN=%s, TAC=%06X, S-NSSAI=", ue.PLMN, 0x000001)
	for _, b := range ue.Snssai {
		fmt.Printf("%02X ", b)
	}
	fmt.Println()

	return nil
}

func (ue *UEContext) handleSecurityModeCommand(message *nas.SecurityModeCommand) {
	if message.Ngksi.Id == 7 || ue.AuthCtx.ngKsi.Id != message.Ngksi.Id || ue.AuthCtx.ngKsi.Tsc != message.Ngksi.Tsc {
		fmt.Println("[UE] Error in Security Mode Command, ngKSI not the expected value")
		return
	}

	algs := message.SelectedNasSecurityAlgorithms

	switch algs.EncAlg() {
	case nas.AlgCiphering128NEA0:
		fmt.Println("[UE] Type of ciphering algorithm is 5G-EA0")
	case nas.AlgCiphering128NEA1:
		fmt.Println("[UE] Type of ciphering algorithm is 128-5G-EA1")
	case nas.AlgCiphering128NEA2:
		fmt.Println("[UE] Type of ciphering algorithm is 128-5G-EA2")
	case nas.AlgCiphering128NEA3:
		fmt.Println("[UE] Type of ciphering algorithm is 128-5G-EA3")
	}

	switch algs.IntAlg() {
	case nas.AlgIntegrity128NIA0:
		fmt.Println("[UE] Type of integrity algorithm is 5G-IA0")
	case nas.AlgIntegrity128NIA1:
		fmt.Println("[UE] Type of integrity algorithm is 128-5G-IA1")
	case nas.AlgIntegrity128NIA2:
		fmt.Println("[UE] Type of integrity algorithm is 128-5G-IA2")
	case nas.AlgIntegrity128NIA3:
		fmt.Println("[UE] Type of integrity algorithm is 128-5G-IA3")
	}

	rinmr := false
	if message.AdditionalSecurityInformation != nil {
		rinmr = message.AdditionalSecurityInformation.GetRetransmission()
		fmt.Printf("[UE] Have Additional Security Information, retransmission = %v\n", rinmr)
	}

	if ue.secCtx != nil {
		nasCtx := ue.secCtx.NasContext(true)
		if nasCtx != nil {
			nasCtx.DeriveKeys(algs.EncAlg(), algs.IntAlg(), ue.secCtx.Kamf())
			fmt.Printf("[UE] NAS keys derived successfully\n")
		} else {
			fmt.Println("[UE] Warning: NAS context is nil, cannot derive keys")
			return
		}
	} else {
		fmt.Println("[UE] Warning: Security context is nil, cannot derive keys")
		return
	}

	imeisv := nas.Imei{IsSv: true}
	imeisv.Parse("1110000000000000")
	response := &nas.SecurityModeComplete{
		Imeisv: &nas.MobileIdentity{
			Id: &imeisv,
		},
	}

	if rinmr {
		response.NasMessageContainer = ue.nasPdu
	}

	response.SetSecurityHeader(nas.NasSecBothNew)
	nasCtx := ue.getNasContext()
	if nasCtx == nil {
		fmt.Println("[UE] Warning: NAS context nil, cannot encode SecurityModeComplete")
		return
	}

	responsePdu, err := nas.EncodeMm(nasCtx, response, false)
	if err != nil {
		fmt.Println("[UE] Encode SecurityModeComplete failed:", err)
		return
	}

	ue.MsgToGnbChan <- responsePdu

	if algs.IntAlg() == nas.AlgIntegrity128NIA0 {
		fmt.Println("[UE] Sent Security Mode Complete============================================")
	} else {
		fmt.Println("[UE] ===== Sent Security Mode Complete (Secured NAS) ===================================================")
	}
}

func (ue *UEContext) handleRegistrationAccept(msg *nas.RegistrationAccept) {
	if msg == nil {
		fmt.Println("Registration Accept is nil")
		return
	}

	fmt.Println("[UE] Processing Registration Accept...")

	resp := &nas.RegistrationComplete{}

	nasCtx := ue.getNasContext()
	if nasCtx == nil {
		fmt.Println("[UE] Warning: NAS context nil, sending plain RegistrationComplete")
		resp.SetSecurityHeader(nas.NasSecNone)
		buf, err := nas.EncodeMm(nil, resp, true)
		if err != nil {
			fmt.Println("Encode RegistrationComplete (plain) failed:", err)
			return
		}
		ue.MsgToGnbChan <- buf
		fmt.Println("Sent Registration Complete (PLAIN) – UE is registered")
		return
	}

	resp.SetSecurityHeader(nas.NasSecBoth)
	buf, err := nas.EncodeMm(nasCtx, resp, false)
	if err != nil {
		fmt.Println("Encode RegistrationComplete failed:", err)
		return
	}

	ue.MsgToGnbChan <- buf
	fmt.Println("[UE] ===== Sent Registration Complete (SECURED) ---> UE is registered =====")
}

func (ue *UEContext) SendUplinkNAS(nasPdu []byte) {
	if len(nasPdu) == 0 {
		fmt.Println("[UE] NAS PDU empty, cannot send UplinkNAS")
		return
	}
	if ue.UplinkNASChan != nil {
		ue.UplinkNASChan <- nasPdu
		fmt.Printf("[UE] Sent UplinkNAS → gNB: %x\n", nasPdu)
	}
}

func (ue *UEContext) TriggerInitPduSessionRequest(sessionId int) {
	fmt.Println("====================== Initiating PDU Session Request, ID:", sessionId)
	if sessionId < 0 || sessionId >= len(ue.sessions) {
		fmt.Println("Invalid PDU Session ID")
		return
	}
	session := &PduSession{id: sessionId, state: PDUSessionInactive}
	ue.sessions[sessionId] = session
	session.SendEventSm(InitPduSessionEstablishmentRequestEvent)
}

func extractMSIN(supi string) string {
	s := strings.TrimPrefix(strings.ToLower(supi), "imsi-")
	if len(s) > 5 {
		return s[5:]
	}
	return s
}

func (ue *UEContext) handleDlNasTransportRaw(nasBytes []byte, secHeaderType uint8) {
	inner := nasBytes
	if secHeaderType != nas.NasSecNone {
		pos := bytes.IndexByte(nasBytes[1:], 0x7e)
		if pos < 0 {
			fmt.Println("[UE] Raw fallback: could not locate inner plain NAS (0x7e)")
			return
		}
		inner = nasBytes[1+pos:]
	}
	if len(inner) < 4 || inner[0] != 0x7e {
		fmt.Println("[UE] Raw fallback: inner NAS malformed")
		return
	}
	if inner[2] != 0x68 {
		fmt.Printf("[UE] Raw fallback: inner MsgType is 0x%02x, not DL NAS Transport\n", inner[2])
		return
	}

	smStartRel := bytes.IndexByte(inner[3:], 0x2e)
	if smStartRel < 0 {
		fmt.Println("[UE] Raw fallback: 5GSM container (0x2e) not found")
		return
	}
	sm := inner[3+smStartRel:]
	if len(sm) < 4 {
		fmt.Println("[UE] Raw fallback: 5GSM header too short")
		return
	}

	pduSessionID := sm[1]
	gsmMsgType := sm[3]

	fmt.Printf("\n[UE] ========== Parsed DL NAS Transport (RAW) ==========\n")
	fmt.Printf("[UE] PDU Session ID: %d\n", pduSessionID)
	fmt.Printf("[UE] 5GSM Message Type: 0x%02x\n", gsmMsgType)

	switch gsmMsgType {
	case 0xC2: // PDU Session Establishment Accept
		fmt.Printf("[UE] ========== PDU Session Establishment ACCEPT (ID=%d) ==========\n", pduSessionID)
		if ue.sessions[pduSessionID] == nil {
			ue.sessions[pduSessionID] = &PduSession{
				id:    int(pduSessionID),
				state: PDUSessionActive,
			}
		} else {
			ue.sessions[pduSessionID].state = PDUSessionActive
		}
		fmt.Printf("[UE] ===== PDU Session %d is now ACTIVE =====\n", pduSessionID)

	case 0xD1: // Reject
		fmt.Printf("[UE] ========== PDU Session Establishment REJECTED (ID=%d) ==========\n", pduSessionID)

	case 0xD3: 
		fmt.Printf("[UE] ========== PDU Session Release Command (ID=%d) ==========\n", pduSessionID)
		if ue.sessions[pduSessionID] != nil {
			// Send Release Complete immediately
			if err := ue.sendPduSessionReleaseComplete(pduSessionID); err != nil {
				fmt.Printf("[UE] ERROR: Failed to send Release Complete: %v\n", err)
			} else {
				fmt.Printf("[UE]  PDU Session %d released and confirmed\n", pduSessionID)
			}
		} else {
			fmt.Printf("[UE] WARNING: PDU Session %d does not exist\n", pduSessionID)
		}

	default:
		fmt.Printf("[UE] Unhandled 5GSM message type (raw): 0x%02x\n", gsmMsgType)
	}
}