package ue

import "github.com/reogac/nas"

type UserEquipment struct {
	SUPI string
	PLMN string

	RanUeNgapId int
	AmfUeNgapId int

	Seq   uint8
	State string

	Snssai []byte
	secCap *nas.UeSecurityCapability
	Suci   nas.MobileIdentity
	nasPdu []byte
	msin   string
}

func NewUserEquipment(supi, plmn string, ranUeNgapId int, mcc, mnc string) *UserEquipment {
	var plmnId nas.PlmnId
	plmnId.Set(mcc, mnc)

	suci := new(nas.SupiImsi)
	suci.Parse([]string{plmnId.String(), "0000000001"})
	return &UserEquipment{
		SUPI:        supi,
		PLMN:        plmn,
		RanUeNgapId: ranUeNgapId,
		AmfUeNgapId: 0,
		Seq:         0,
		State:       "DEREGISTERED",
		Snssai:      nil,
		Suci: nas.MobileIdentity{
			Id: &nas.Suci{
				Content: suci,
			},
		},
	}
}

func (ue *UserEquipment) CreateSuci(mcc, mnc string) {

}
