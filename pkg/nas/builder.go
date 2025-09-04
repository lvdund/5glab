package nas

import (
	"5g-emulator/internal/UE/context"
	"fmt"
	"log"

	"github.com/reogac/nas"
)

func BuildRegistrationRequest(ueCtx *context.UEConfig) ([]byte, error) {
	log.Println("INFO: --- [UE - Step 3a] Building NAS Registration Request ---")

	msg := new(nas.RegistrationRequest)

	msg.SetSecurityHeader(1)

	msg.Ngksi = nas.KeySetIdentifier{
		Tsc: 0,
		Id:  7,
	}

	msg.RegistrationType = nas.NewRegistrationType(true, nas.RegistrationType5GSInitialRegistration)

	supiImsi := &nas.SupiImsi{}
	plmn := ueCtx.IMSI[0:5]
	msin := ueCtx.IMSI[5:]
	if err := supiImsi.Parse([]string{plmn, msin}); err != nil {
		return nil, fmt.Errorf("failed to parse SUPI/IMSI: %w", err)
	}
	msg.MobileIdentity.Id = &nas.Suci{
		Content: supiImsi,
	}

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

func HandleNASMessage(ueCtx *context.UEContext, pdu []byte) {

	nasCtx := nas.NewNasContext(false)
	nasMsg, err := nas.Decode(nasCtx, pdu, false)
	if err != nil {
		log.Printf("ERROR: [UE] Failed to decode NAS message: %v", err)
		return
	}

	if nasMsg.Gmm != nil {
		switch nasMsg.Gmm.MsgType {
		case nas.AuthenticationRequestMsgType:
			log.Println("SUCCESS: [UE] Received Authentication Request!")

		default:
			log.Printf("WARN: [UE] Received unhandled GMM message type: 0x%02x", nasMsg.Gmm.MsgType)
		}
	} else {
		log.Println("WARN: [UE] Received a NAS message with no GMM content.")
	}
}
