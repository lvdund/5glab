package ue

import (
	"github.com/reogac/nas"
)

func (ue *UserEquipment) BuildRegistrantionUeMsg() (*nas.RegistrationRequest, []byte, error) {
	if len(ue.Snssai) == 0 {
		ue.Snssai = []byte{0x01, 0x01, 0x02, 0x03}
	}
	msg := &nas.RegistrationRequest{
		RegistrationType: nas.NewRegistrationType(true, nas.RegistrationType5GSInitialRegistration),
		MobileIdentity: nas.MobileIdentity{
			Id: &nas.Guti{},
		},
		Ngksi: nas.KeySetIdentifier{Tsc: 1, Id: 0},
	}
	msg.SetSecurityHeader(0)
	buf, err := nas.EncodeMm(nil, msg, true)
	if err != nil {
		return msg, nil, err
	}
	return msg, buf, err
}
