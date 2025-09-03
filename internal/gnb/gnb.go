package gnb

import "log"

type Gnb struct {
	GnbID uint32
	PLMN  string
	TAC   uint32
	IP    string
	Port  int
}

func NewGnbContext(gnbID, tac uint32, port int, plmn, ip string) *Gnb {
	return &Gnb{
		GnbID: gnbID,
		PLMN:  plmn,
		TAC:   tac,
		IP:    ip,
		Port:  port,
	}
}

func (gnb *Gnb) getMccAndMncInOctets() []byte {
	if len(gnb.PLMN) < 5 || len(gnb.PLMN) > 6 {
		log.Fatalf("Invalid PLMN length: %s", gnb.PLMN)
	}
	mcc := gnb.PLMN[:3]
	mnc := gnb.PLMN[3:]

	var mnc0, mnc1, mnc2 byte
	if len(mnc) == 2 {
		mnc0 = mnc[0] - '0'
		mnc1 = mnc[1] - '0'
		mnc2 = 0xF
	} else {
		mnc0 = mnc[0] - '0'
		mnc1 = mnc[1] - '0'
		mnc2 = mnc[2] - '0'
	}

	return []byte{
		((mcc[1]-'0')<<4 | (mcc[0] - '0')),
		((mnc2)<<4 | (mcc[2] - '0')),
		((mnc1)<<4 | (mnc0)),
	}
}

func (gnb *Gnb) getGnbIdInBytes() []byte {
	return []byte{0x01, 0x02, 0x03}
}

// convert TAC -> 3 bytes
func (gnb *Gnb) getTacInBytes() []byte {
	return []byte{
		byte((gnb.TAC >> 16) & 0xff),
		byte((gnb.TAC >> 8) & 0xff),
		byte(gnb.TAC & 0xff),
	}
}
