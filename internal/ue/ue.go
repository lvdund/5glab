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
	SecCap *nas.UeSecurityCapability
	Suci   nas.MobileIdentity
	nasPdu []byte
	msin   string
}

func NewUserEquipment(supi, plmn string, ranUeNgapId int, mcc, mnc string) *UserEquipment {
	//suci
	var plmnId nas.PlmnId
	plmnId.Set(mcc, mnc)
	suci := new(nas.SupiImsi)
	suci.Parse([]string{plmnId.String(), "0000000001"})

	//sec cap
	secCap := new(nas.UeSecurityCapability) //2 bytes

	// Ciphering algorithms
	secCap.SetEA(0, true)
	secCap.SetEA(1, false)
	secCap.SetEA(2, true)
	secCap.SetEA(3, false)

	// Integrity algorithms
	secCap.SetIA(0, false)
	secCap.SetIA(1, false)
	secCap.SetIA(2, true)
	secCap.SetIA(3, false)
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
		SecCap: secCap,
	}
}
