package model

import (
	"time"

	"github.com/lvdund/ngap/ies"
)

type GnbPDUSession struct {
	Teid
	Snssai
	PduSessionId int64
	UpfIp        string
	PduType      uint64
	QosId        int64
	FiveQi       int64
	PriArp       int64
}

type Teid struct {
	UplinkTeid   uint32
	DownlinkTeid uint32
}

type PagedUE struct {
	FiveGSTMSI *ies.FiveGSTMSI
	Timestamp  time.Time
}

func (pduSession *GnbPDUSession) GetPduSessionId() int64 {
	return pduSession.PduSessionId
}

func (pduSession *GnbPDUSession) GetUpfIp() string {
	return pduSession.UpfIp
}

func (pduSession *GnbPDUSession) GetTeidUplink() uint32 {
	return pduSession.UplinkTeid
}

func (pduSession *GnbPDUSession) GetTeidDownlink() uint32 {
	return pduSession.DownlinkTeid
}

func (pduSession *GnbPDUSession) GetPduType() (sessionType string) {

	switch pduSession.PduType {
	case 0:
		sessionType = "ipv4"
	case 1:
		sessionType = "ipv6"
	case 2:
		sessionType = "Ipv4Ipv6"
	case 3:
		sessionType = "ethernet"

	}
	return
}

type UeCoreContext struct {
	MobilityInfo           Plmn
	MaskedIMEISV           string
	PduSession             [16]*GnbPDUSession
	AllowedSnssai          []Snssai
	LenSlice               int
	UeSecurityCapabilities *ies.UESecurityCapabilities
}
