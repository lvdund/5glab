package uecontext

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"emulator/internal/uecontext/sec"

	"github.com/reogac/nas"
)

// Dummy PDU Session state
const (
	PDUSessionInactive = 0
	PDUSessionActive   = 1
)

// Dummy event constants
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

// Getter NAS context
func (ue *UEContext) getNasContext() *nas.NasContext {
	if ue.secCtx == nil {
		return nil
	}
	return ue.secCtx.NasContext(true)
}

// NAS handlers loop
func (ue *UEContext) HandlerNasMsg() {
	timeout := 20 * time.Second
	for {
		select {
		case msg := <-ue.MsgFromGnbChan:
			fmt.Println("[UE] Received NAS from gNB, len:", len(msg))
			//  fmt.Printf("[UE] Raw NAS: %x\n", msg)
			ue.handleNasMsg(msg)
		case <-time.After(timeout):
			fmt.Println("[UE] Timeout waiting for NAS message from gNB, continue...")
		}
	}
}

func (ue *UEContext) handleNasMsg(nasBytes []byte) {
	if len(nasBytes) == 0 {
		fmt.Println("NAS message is empty")
		return
	}

	secHeaderType := nasBytes[0] >> 4

	nasCtx := nas.NewNasContext(false)
	nasMsg, err := nas.Decode(nasCtx, nasBytes, false)
	if err != nil {
		fmt.Println("Decode NAS message failed:", err)
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

	default:
		fmt.Printf("Received unknown NAS GMM message type: 0x%x\n", gmm.MsgType)
	}
}

// Identity Request handler
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

	var buf []byte
	var encErr error

	buf, encErr = nas.EncodeMm(nil, resp, true)
	if encErr == nil {
		ue.MsgToGnbChan <- buf
		fmt.Println("Sent Identity Response (Plain NAS) via EncodeMm(nil, resp, true)")
		return
	}
	fmt.Println("Encode IdentityResponse attempt 1 failed:", encErr)
	buf, encErr = nas.EncodeMm(nas.NewNasContext(false), resp, false)
	if encErr == nil {
		ue.MsgToGnbChan <- buf
		fmt.Println("Sent Identity Response (Plain NAS) via EncodeMm(NewNasContext(false), resp, false)")
		return
	}
	fmt.Println("Encode IdentityResponse attempt 2 failed:", encErr)
	buf, encErr = nas.EncodeMm(nas.NewNasContext(true), resp, false)
	if encErr == nil {
		ue.MsgToGnbChan <- buf
		fmt.Println("Sent Identity Response (Plain NAS) via EncodeMm(NewNasContext(true), resp, false)")
		return
	}
	fmt.Println("Encode IdentityResponse attempt 3 failed:", encErr)
	fmt.Println("All attempts to encode IdentityResponse failed.")
}

// Authentication Request handler
func (ue *UEContext) handleAuthenticationRequest(msg *nas.AuthenticationRequest) {
	if msg == nil {
		fmt.Println("Authentication Request is nil")
		return
	}

	if len(msg.AuthenticationParameterRand) == 0 || len(msg.AuthenticationParameterAutn) == 0 {
		fmt.Println("RAND or AUTN missing in Authentication Request")
		return
	}

	// save RAND and AUTN
	ue.AuthCtx.rand = msg.AuthenticationParameterRand
	autn := msg.AuthenticationParameterAutn
	abba := msg.Abba

	fmt.Printf("[UE] Received AUTN: %x\n", autn)
	fmt.Printf("[UE] Stored RAND: %x\n", ue.AuthCtx.rand)

	// compute res
	errCode, resStar := ue.AuthCtx.ProcessAuthenticationInfo(autn, abba)
	if errCode != AUTH_SUCCESS {
		fmt.Println("[UE] Authentication failed, cannot compute RES*")
		return
	}

	fmt.Printf("[DEBUG] Computed KAMF: %x\n", ue.AuthCtx.kamf)
	fmt.Printf("[DEBUG] RES*: %x\n", resStar)

	fmt.Println("Authentication success")
	fmt.Printf("[UE] RES*: %x, len=%d\n", resStar, len(resStar))
	// create SecurityContext now that we have KAMF
	if ue.AuthCtx != nil && len(ue.AuthCtx.kamf) > 0 {
		ue.secCtx = sec.NewSecurityContext(&ue.AuthCtx.ngKsi, ue.AuthCtx.kamf, false)
		fmt.Printf("[UE] SecurityCtx created with KAMF: %x\n", ue.AuthCtx.kamf)
	} else {
		fmt.Println("[UE] Warning: no KAMF available after authentication")
	}

	// build NAS message response
	msgResp := &nas.AuthenticationResponse{
		AuthenticationResponseParameter: resStar,
	}
	msgResp.SetSecurityHeader(nas.NasSecNone)

	// Encode NAS PDU
	responsePdu, err := nas.EncodeMm(nil, msgResp, true)
	fmt.Printf("[UE] Authentication Response PDU: %x\n", responsePdu)

	if err != nil {
		fmt.Println("Encode Authentication message failed:", err)
		return
	}

	if len(responsePdu) == 0 {
		fmt.Println("Encoded NAS PDU is empty, skip sending")
		return
	}

	// send response to gNB
	ue.MsgToGnbChan <- responsePdu
	fmt.Println("===========================================Sent Authentication Response (plain NAS)")
}

// Trigger Registration (uplink initial)
func (ue *UEContext) TriggerInitRegistration() error {
	if len(ue.Snssai) == 0 {
		ue.Snssai = []byte{0x01, 0x01, 0x02, 0x03}
	}

	ueSecCap := &nas.UeSecurityCapability{}
	ueSecCap.SetEA(0, true) // NEA0
	ueSecCap.SetEA(1, true) // 128-NEA1
	ueSecCap.SetEA(2, true) // 128-NEA2
	ueSecCap.SetIA(0, true) // NIA0
	ueSecCap.SetIA(1, true) // 128-NIA1
	ueSecCap.SetIA(2, true) // 128-NIA2

	suci := new(nas.SupiImsi)
	suci.Parse([]string{"208", "93", "0000", "0", "1", "0000000001"})

	msg := &nas.RegistrationRequest{
		RegistrationType: nas.NewRegistrationType(true, nas.RegistrationType5GSInitialRegistration),
		MobileIdentity: nas.MobileIdentity{
			Id: &nas.Suci{Content: suci},
		},
		Ngksi:                nas.KeySetIdentifier{Tsc: 1, Id: 0},
		UeSecurityCapability: ueSecCap,
	}

	msg.SetSecurityHeader(nas.NasSecNone)
	buf, err := nas.EncodeMm(nil, msg, true)
	if err != nil {
		fmt.Println("Failed to encode RegistrationRequest:", err)
		return err
	}

	ue.MsgToGnbChan <- buf

	fmt.Printf("================= NAS RegistrationRequest sent: PLMN=%s, TAC=%06X, S-NSSAI=", ue.PLMN, 0x000001)
	for _, b := range ue.Snssai {
		fmt.Printf("%02X ", b)
	}
	fmt.Println()

	return nil
}

// Security Mode Command handler
func (ue *UEContext) handleSecurityModeCommand(msg *nas.SecurityModeCommand) {
	if msg == nil {
		fmt.Println("Security Mode Command is nil")
		return
	}

	// Log selected algorithms
	algs := msg.SelectedNasSecurityAlgorithms
	switch algs.EncAlg() {
	case nas.AlgCiphering128NEA0:
		fmt.Println("[UE] Ciphering algorithm: 5G-0")
	case nas.AlgCiphering128NEA1:
		fmt.Println("[UE] Ciphering algorithm: 128-5G-1")
	case nas.AlgCiphering128NEA2:
		fmt.Println("[UE] Ciphering algorithm: 128-5G-2")
	case nas.AlgCiphering128NEA3:
		fmt.Println("[UE] Ciphering algorithm: 128-5G-3")
	}

	switch algs.IntAlg() {
	case nas.AlgIntegrity128NIA0:
		fmt.Println("[UE] Integrity algorithm: 5G-IA0")
	case nas.AlgIntegrity128NIA1:
		fmt.Println("[UE] Integrity algorithm: 128-5G-IA1")
	case nas.AlgIntegrity128NIA2:
		fmt.Println("[UE] Integrity algorithm: 128-5G-IA2")
	case nas.AlgIntegrity128NIA3:
		fmt.Println("[UE] Integrity algorithm: 128-5G-IA3")
	}

	// Derive NAS keys
	nasCtx := ue.getNasContext()
	if nasCtx == nil {
		fmt.Println("[UE] getNasContext() returned nil, cannot derive keys")
		return
	}
	if err := nasCtx.DeriveKeys(algs.EncAlg(), algs.IntAlg(), []byte{sec.HDP_NONE}); err != nil {
		fmt.Println("DeriveNasKeys failed:", err)
		return
	}
	// Build SecurityModeComplete
	imeisv := nas.Imei{IsSv: true}
	imeisv.Parse("1110000000000000") // dummy IMEI
	resp := &nas.SecurityModeComplete{
		Imeisv: &nas.MobileIdentity{Id: &imeisv},
	}

	// Optional: include Additional Security Information (RINMR)
	if msg.AdditionalSecurityInformation != nil {
		resp.NasMessageContainer = ue.nasPdu
		fmt.Println("[UE] Additional Security Info present, included NAS PDU in container")
	}

	resp.SetSecurityHeader(nas.NasSecBothNew)

	// Log counters
	fmt.Printf("[UE] UL NAS count: %d, DL NAS count: %d\n", nasCtx.UlCounter(), nasCtx.DlCounter())

	// Encode and send
	buf, err := nas.EncodeMm(nasCtx, resp, false)
	if err != nil {
		fmt.Println("Encode SecurityModeComplete failed:", err)
		return
	}

	ue.MsgToGnbChan <- buf
	fmt.Println("====================== Sent Security Mode Complete")
}

// Registration Accept handler
func (ue *UEContext) handleRegistrationAccept(msg *nas.RegistrationAccept) {
	if msg == nil {
		fmt.Println("Registration Accept is nil")
		return
	}

	resp := &nas.RegistrationComplete{}
	buf, err := nas.EncodeMm(nas.NewNasContext(false), resp, false)
	if err != nil {
		fmt.Println("Encode RegistrationComplete failed:", err)
		return
	}

	ue.MsgToGnbChan <- buf
	fmt.Println("Sent Registration Complete – UE is registered")
}

// Misc
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

// Dummy PDU Session trigger
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
