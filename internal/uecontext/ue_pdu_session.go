package uecontext

import (
	"fmt"
	"github.com/reogac/nas"
)

// TriggerPduSessionEstablishment - Create PDU Session Establishment Request
func (ue *UEContext) TriggerPduSessionEstablishment(sessionID uint8, dnn string) error {
	if sessionID < 1 || sessionID > 15 {
		return fmt.Errorf("invalid PDU Session ID: %d", sessionID)
	}

	fmt.Printf("\n[UE] ========== Initiating PDU Session Establishment (ID=%d, DNN=%s) ==========\n", sessionID, dnn)

	n1Sm := &nas.PduSessionEstablishmentRequest{}
	pduType := nas.PduSessionTypeIpv4
	n1Sm.PduSessionType = &pduType
	n1Sm.IntegrityProtectionMaximumDataRate = nas.NewIntegrityProtectionMaximumDataRate(0xff, 0xff)
	n1Sm.SetPti(1)
	n1Sm.SetSessionId(sessionID)

	n1SmPdu, err := nas.EncodeSm(n1Sm)
	if err != nil {
		return fmt.Errorf("failed to encode PDU Session Establishment Request: %v", err)
	}

	requestType := nas.UlNasTransportRequestTypeInitialRequest
	params := make(map[string]any)
	if dnn != "" {
		params["dnn"] = dnn
	}

	err = ue.sendN1Sm(n1SmPdu, sessionID, &requestType, &params)
	if err != nil {
		return fmt.Errorf("failed to send N1 SM: %v", err)
	}

	fmt.Println("[UE] ===== Sent PDU Session Establishment Request =====")
	return nil
}

// sendN1Sm - Helper to send 5GSM message via UL NAS Transport
func (ue *UEContext) sendN1Sm(n1SmPdu []byte, sessionID uint8, requestType *uint8, params *map[string]any) error {
	ulNasTransport := &nas.UlNasTransport{
		PayloadContainerType: nas.PayloadContainerTypeN1SMInfo,
		PayloadContainer:     n1SmPdu,
		PduSessionId:         &sessionID,
	}

	ulNasTransport.SNssai = &nas.SNssai{
		Sst: 0x01,
		Sd:  []byte{0x01, 0x02, 0x03},
	}

	if requestType != nil {
		ulNasTransport.RequestType = requestType
	}

	if params != nil {
		if dnnVal, ok := (*params)["dnn"]; ok {
			if dnnStr, ok := dnnVal.(string); ok && dnnStr != "" {
				ulNasTransport.Dnn = nas.NewDnn(dnnStr)
			}
		}
	}

	nasCtx := ue.getNasContext()
	if nasCtx == nil {
		return fmt.Errorf("NAS security context not available")
	}

	ulNasTransport.SetSecurityHeader(nas.NasSecBoth)
	nasPdu, err := nas.EncodeMm(nasCtx, ulNasTransport, true)
	if err != nil {
		return fmt.Errorf("failed to encode UL NAS Transport: %v", err)
	}

	ue.MsgToGnbChan <- nasPdu
	fmt.Printf("[UE] Sent N1 SM message (Session ID=%d, %d bytes)\n", sessionID, len(nasPdu))
	return nil
}

// TriggerPduSessionRelease - Initiate PDU Session Release Request
func (ue *UEContext) TriggerPduSessionRelease(sessionID uint8) error {
	if sessionID < 1 || sessionID > 15 {
		return fmt.Errorf("invalid PDU Session ID: %d", sessionID)
	}

	fmt.Printf("\n[UE] ========== Initiating PDU Session Release (ID=%d) ==========\n", sessionID)

	if ue.sessions[sessionID] == nil {
		return fmt.Errorf("PDU Session %d does not exist", sessionID)
	}

	if ue.sessions[sessionID].state != PDUSessionActive {
		return fmt.Errorf("PDU Session %d is not active (state=%d)", sessionID, ue.sessions[sessionID].state)
	}

	n1Sm := &nas.PduSessionReleaseRequest{}
	n1Sm.SetPti(1)
	n1Sm.SetSessionId(sessionID)

	n1SmPdu, err := nas.EncodeSm(n1Sm)
	if err != nil {
		return fmt.Errorf("failed to encode PDU Session Release Request: %v", err)
	}

	err = ue.sendN1Sm(n1SmPdu, sessionID, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to send N1 SM: %v", err)
	}

	fmt.Println("[UE] ===== Sent PDU Session Release Request =====")
	return nil
}


// sendPduSessionReleaseComplete - Send Release Complete after receiving Release Command
func (ue *UEContext) sendPduSessionReleaseComplete(sessionID uint8) error {
	fmt.Printf("[UE] ========== Sending PDU Session Release Complete (ID=%d) ==========\n", sessionID)

	// Create Release Complete message
	n1Sm := &nas.PduSessionReleaseComplete{}
	n1Sm.SetPti(1)
	n1Sm.SetSessionId(sessionID)

	// Encode 5GSM message
	n1SmPdu, err := nas.EncodeSm(n1Sm)
	if err != nil {
		return fmt.Errorf("failed to encode PDU Session Release Complete: %v", err)
	}

	// Send via UL NAS Transport
	err = ue.sendN1Sm(n1SmPdu, sessionID, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to send Release Complete: %v", err)
	}

	// Mark session as inactive
	if ue.sessions[sessionID] != nil {
		ue.sessions[sessionID].state = PDUSessionInactive
	}

	fmt.Printf("[UE] ===== PDU Session %d Release Complete sent =====\n", sessionID)
	return nil
}