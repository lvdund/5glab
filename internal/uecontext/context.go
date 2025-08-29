package uecontext

type UEContext struct {
    SUPI string
    PLMN string

    // NGAP
    RanUeNgapId int
    AmfUeNgapId int

    // nas
    Seq   uint8
    State string

    // s-nssai
    Snssai []byte
}

// UEContext
func NewUEContext(supi, plmn string, ranUeNgapId int) *UEContext {
    return &UEContext{
        SUPI:        supi,
        PLMN:        plmn,
        RanUeNgapId: ranUeNgapId,
        AmfUeNgapId: 0,
        Seq:         0,
        State:       "DEREGISTERED",
        Snssai:      nil, 
    }
}
