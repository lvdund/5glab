package gnb

import (
	"log"

	"github.com/Phuc12012005/emulator/internal/ue"
	"github.com/lvdund/ngap"
	"github.com/lvdund/ngap/aper"
	"github.com/lvdund/ngap/ies"
	"github.com/reogac/nas"
)

func BuildRegistrationRequest(ue *ue.UserEquipment) ([]byte, error) {
	rr := &nas.RegistrationRequest{
		RegistrationType: nas.NewRegistrationType(true, nas.RegistrationType5GSInitialRegistration),
		Ngksi: nas.KeySetIdentifier{
			Tsc: 1,
			Id:  1,
		},
		MobileIdentity: ue.Suci,
	}
	rr.SetSecurityHeader(0)
	buf, err := nas.EncodeMm(nil, rr, true)
	if err != nil {
		log.Fatalln("encode rr failed", err)
	}
	return buf, err
}
func BuildInitialUeMessage(nasPdu []byte) ([]byte, error) {
	msg := ies.InitialUEMessage{}

	msg.RANUENGAPID = 1000

	// Attach the NAS Registration Request
	msg.NASPDU = nasPdu

	// PLMN = MCC 001 / MNC 01 → octets 0x00 0xF1
	plmnid := []byte{0x21, 0xF8, 0x39}
	//plmnidTai := []byte{0x00, 0xF1}

	// NR Cell Identity (36 bits, padded to 5 bytes)
	// Example: CellID = 0x12345
	cellid := aper.BitString{
		Bytes:   []byte{0x00, 0x12, 0x34, 0x56, 0x00},
		NumBits: 36,
	}

	// TAC = 1 → 0x0001
	tac := []byte{0x00, 0x00, 0x01}

	// User Location Info (NR)
	msg.UserLocationInformation = ies.UserLocationInformation{
		Choice: ies.UserLocationInformationPresentUserlocationinformationnr,
		UserLocationInformationNR: &ies.UserLocationInformationNR{
			NRCGI: ies.NRCGI{
				PLMNIdentity:   plmnid,
				NRCellIdentity: cellid,
			},
			TAI: ies.TAI{
				PLMNIdentity: plmnid,
				TAC:          tac,
			},
		},
	}

	msg.RRCEstablishmentCause = ies.RRCEstablishmentCause{
		Value: ies.RRCEstablishmentCauseMosignalling,
	}
	return ngap.NgapEncode(&msg)
}
