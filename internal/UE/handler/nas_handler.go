package handler

import (
	"5g-emulator/internal/UE/context"
	"5g-emulator/pkg/logger"
	"5g-emulator/pkg/security"
	"fmt"
	"log"

	"github.com/reogac/nas"
)

func BuildRegistrationRequest(ueCtx *context.UEContext) ([]byte, error) {
	log.Println("INFO: --- [UE - Step 3a] Building NAS Registration Request ---")

	msg := new(nas.RegistrationRequest)

	msg.SetSecurityHeader(1)

	msg.RegistrationType = nas.NewRegistrationType(true, nas.RegistrationType5GSInitialRegistration)

	msg.Ngksi = nas.KeySetIdentifier{Tsc: 0, Id: 7}

	supiImsi := &nas.SupiImsi{}
	plmn := ueCtx.Config.IMSI[0:5]
	msin := ueCtx.Config.IMSI[5:]
	if err := supiImsi.Parse([]string{plmn, msin}); err != nil {
		return nil, fmt.Errorf("failed to parse SUPI/IMSI: %w", err)
	}
	msg.MobileIdentity.Id = &nas.Suci{Content: supiImsi}

	msg.UeSecurityCapability = &nas.UeSecurityCapability{}
	msg.UeSecurityCapability.SetEA(0, true)
	msg.UeSecurityCapability.SetEA(1, true)
	msg.UeSecurityCapability.SetEA(2, true)
	msg.UeSecurityCapability.SetIA(0, true)
	msg.UeSecurityCapability.SetIA(1, true)
	msg.UeSecurityCapability.SetIA(2, true)

	nasCtx := nas.NewNasContext(false)
	data, err := nas.EncodeMm(nasCtx, msg, false)
	if err != nil {
		return nil, fmt.Errorf("failed to encode NAS Registration Request: %w", err)
	}

	log.Println("INFO: NAS Registration Request built successfully.")
	return data, nil
}

func ListenForDownlink(ueCtx *context.UEContext) {
	log.Println("INFO: [UE] Starting Downlink NAS message listener...")

	for nasPDU := range ueCtx.Radio.DownlinkChan {
		log.Println("INFO: [UE] Received NAS message from gNB.")
		handleNASMessage(ueCtx, nasPDU)
	}
}

func handleNASMessage(ueCtx *context.UEContext, pdu []byte) {
	nasCtx := nas.NewNasContext(false)
	nasMsg, err := nas.Decode(nasCtx, pdu, false)
	if err != nil {
		log.Printf("ERROR: [UE] Failed to decode NAS message: %v", err)
		return
	}

	if nasMsg.Gmm != nil {
		switch nasMsg.Gmm.MsgType {
		case nas.AuthenticationRequestMsgType:
			log.Println("INFO: [UE] Received Authentication Request.")

			authRequest := nasMsg.Gmm.AuthenticationRequest
			rand := authRequest.AuthenticationParameterRand
			autn := authRequest.AuthenticationParameterAutn

			securityResult, err := security.HandleAuthenticationChallenge(ueCtx, rand, autn)
			if err != nil {
				log.Printf("ERROR: [UE] Authentication procedure failed: %v", err)
				return
			}

			log.Println("INFO: [UE] Authentication successful. New security context established.")
			ueCtx.SecurityContext.NgKSI = authRequest.Ngksi
			ueCtx.SecurityContext.Kamf = securityResult.KAMF
			ueCtx.SecurityContext.UplinkNASCount = 0
			ueCtx.SecurityContext.DownlinkNASCount = 0

			resStar := securityResult.RES_star

			responsePDU, err := BuildAuthenticationResponse(ueCtx, resStar)
			if err != nil {
				log.Printf("ERROR: [UE] Failed to build Authentication Response: %v", err)
				return
			}

			ueCtx.Radio.UplinkChan <- responsePDU
			log.Println("INFO: [UE] Sent Authentication Response to gNB.")

		default:

			log.Printf("WARN: [UE] Received unhandled GMM message type: 0x%02x", nasMsg.Gmm.MsgType)
		}
	}
}

func BuildAuthenticationResponse(ueCtx *context.UEContext, res []byte) ([]byte, error) {
	log.Println("INFO: --- [UE - Step 5a] Building NAS Authentication Response ---")

	msg := new(nas.AuthenticationResponse)
	msg.SetSecurityHeader(1)
	msg.AuthenticationResponseParameter = res

	nasCtx := nas.NewNasContext(false)
	data, err := nas.EncodeMm(nasCtx, msg, false)
	if err != nil {
		return nil, fmt.Errorf("failed to encode NAS Authentication Response: %w", err)
	}

	logger.LogMessageContent("UE -> gNB: NAS AuthenticationResponse", msg)
	return data, nil
}
