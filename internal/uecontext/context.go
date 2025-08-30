package uecontext

type UEContext struct {
	SUPI string
	PLMN string

	// NGAP
	RanUeNgapId int
	AmfUeNgapId int

	// s-nssai
	Snssai []byte

	MsgFromGnbChan chan []byte
	MsgToGnbChan   chan []byte
}

// UEContext
func NewUEContext(supi, plmn string, ranUeNgapId int, MsgFromGnbChan, MsgToGnbChan chan []byte) *UEContext {
	return &UEContext{
		SUPI:           supi,
		PLMN:           plmn,
		RanUeNgapId:    ranUeNgapId,
		AmfUeNgapId:    0,
		Snssai:         []byte{0x01, 0x01, 0x02, 0x03},
		MsgFromGnbChan: MsgFromGnbChan,
		MsgToGnbChan:   MsgToGnbChan,
	}
}

func (ue *UEContext) HandlerNasMsg() {
	for msg := range ue.MsgFromGnbChan {
		ue.handleNasPdu(msg)
	}
}
