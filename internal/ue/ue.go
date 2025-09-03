package ue

type UserEquipment struct {
	SUPI string
	PLMN string

	RanUeNgapId int
	AmfUeNgapId int

	Seq   uint8
	State string

	Snssai []byte
}

func NewUserEquipment(supi, plmn string, ranUeNgapId int) *UserEquipment {
	return &UserEquipment{
		SUPI:        supi,
		PLMN:        plmn,
		RanUeNgapId: ranUeNgapId,
		AmfUeNgapId: 0,
		Seq:         0,
		State:       "DEREGISTERED",
		Snssai:      nil,
	}
}
