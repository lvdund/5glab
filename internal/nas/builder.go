package nas

import (
	"fmt"

	"github.com/reogac/nas"
)

// UEContext Snssai
type UEContext struct {
	SUPI   string
	PLMN   string
	RanUeNgapId int
	AmfUeNgapId int
	State  string
	Snssai []byte 
}

// BuildRegistrationRequest build NAS Registration Request with S-NSSAI
func BuildRegistrationRequest(ue *UEContext) (*nas.RegistrationRequest, []byte, error) {
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

	// Set Security Header
	msg.SetSecurityHeader(0)

	// Encode NAS message
	buf, err := nas.EncodeMm(nil, msg, true)
	if err != nil {
		return msg, nil, err
	}

    // debug 
	fmt.Printf("NAS RegistrationRequest: PLMN=%s, TAC=%06X, S-NSSAI=", ue.PLMN, 0x000001)
	for _, b := range ue.Snssai {
		fmt.Printf("%02X ", b)
	}
	fmt.Println()

	return msg, buf, nil
}
