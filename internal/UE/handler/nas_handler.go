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
		var responsePDU []byte
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

			responsePDU, err = BuildAuthenticationResponse(ueCtx, resStar)
			if err != nil {
				log.Printf("ERROR: [UE] Failed to build Authentication Response: %v", err)
				return
			}

			ueCtx.Radio.UplinkChan <- responsePDU
			log.Println("INFO: [UE] Sent Authentication Response to gNB.")

		case nas.SecurityModeCommandMsgType:
			log.Println("INFO: [UE] Received Security Mode Command.")
			smc := nasMsg.Gmm.SecurityModeCommand

			encAlg := smc.SelectedNasSecurityAlgorithms.EncAlg()
			intAlg := smc.SelectedNasSecurityAlgorithms.IntAlg()

			err := ueCtx.ActivateNasSecurity(encAlg, intAlg)
			if err != nil {
				log.Printf("ERROR: [UE] Failed to activate NAS security: %v", err)
				return
			}

			responsePDU, err = BuildSecurityModeComplete(ueCtx, ueCtx.SecurityContext.NasContext)
			if err != nil {
				log.Printf("ERROR: [UE] Failed to build Security Mode Complete: %v", err)
				return
			}

			ueCtx.Radio.UplinkChan <- responsePDU
			log.Println("INFO: [UE] Sent Security Mode Complete to gNB.")

			responsePDU, err = BuildSecurityModeComplete(ueCtx, ueCtx.SecurityContext.NasContext)
			if err != nil {
				log.Printf("ERROR: [UE] Failed to build Security Mode Complete: %v", err)
				return
			}

			ueCtx.Radio.UplinkChan <- responsePDU
			log.Println("INFO: [UE] Sent Security Mode Complete to gNB.")

		case nas.RegistrationAcceptMsgType:
			log.Println("INFO: [UE] Received Registration Accept.")
			regAccept := nasMsg.Gmm.RegistrationAccept

			if regAccept.Guti != nil {
				if guti, ok := regAccept.Guti.Id.(*nas.Guti); ok {
					ueCtx.GUTI = guti
					log.Printf("INFO: [UE] GUTI updated to: %s", ueCtx.GUTI.String())
				} else {
					log.Printf("WARN: [UE] Received a Mobile Identity in Registration Accept, but it was not a GUTI.")
				}
			}

			ueCtx.State = context.Registered
			log.Println("SUCCESS: [UE] UE is now in REGISTERED state.")

			nasSecCtx := ueCtx.SecurityContext.NasContext

			responsePDU, err = BuildRegistrationComplete(ueCtx, nasSecCtx)
			if err != nil {
				log.Printf("ERROR: [UE] Failed to build Registration Complete: %v", err)
				return
			}

			ueCtx.Radio.UplinkChan <- responsePDU
			log.Println("INFO: [UE] Sent Registration Complete to gNB. Registration procedure finished.")

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

func BuildSecurityModeComplete(ueCtx *context.UEContext, nasCtx *nas.NasContext) ([]byte, error) {
	log.Println("INFO: --- [UE] Building NAS Security Mode Complete ---")

	msg := new(nas.SecurityModeComplete)

	msg.SetSecurityHeader(2)

	data, err := nas.EncodeMm(nasCtx, msg, true)
	if err != nil {
		return nil, fmt.Errorf("failed to encode NAS Security Mode Complete: %w", err)
	}

	logger.LogMessageContent("UE -> gNB: NAS SecurityModeComplete", msg)
	return data, nil
}

func BuildRegistrationComplete(ueCtx *context.UEContext, nasCtx *nas.NasContext) ([]byte, error) {
	log.Println("INFO: --- [UE] Building NAS Registration Complete ---")

	msg := new(nas.RegistrationComplete)

	msg.SetSecurityHeader(3)

	data, err := nas.EncodeMm(nasCtx, msg, true)
	if err != nil {
		return nil, fmt.Errorf("failed to encode NAS Registration Complete: %w", err)
	}

	logger.LogMessageContent("UE -> gNB: NAS RegistrationComplete", msg)
	return data, nil
}
