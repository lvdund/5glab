package context

import (
	ue_context "5g-emulator/internal/UE/context"

	"5g-emulator/internal/radio"

	"github.com/ishidawataru/sctp"
)

type GNBConfig struct {
	MCC     string `yaml:"mcc"`
	MNC     string `yaml:"mnc"`
	TAC     int    `yaml:"tac"`
	GNBID   string `yaml:"gnbId"`
	GNBName string `yaml:"gnbName"`
}

type GNBContext struct {
	Config       *GNBConfig
	SCTPConn     *sctp.SCTPConn
	UEContext    *ue_context.UEContext
	AmfUeNgapID  int64
	RanUeNgapID  int64
	DownlinkChan chan []byte
	Radio        *radio.RadioLink
}

func NewGNBContext(cfg *GNBConfig, conn *sctp.SCTPConn, radioLink *radio.RadioLink) *GNBContext {
	return &GNBContext{
		Config:      cfg,
		SCTPConn:    conn,
		RanUeNgapID: 1,
		Radio:       radioLink,
	}
}

func (gnb *GNBContext) SetUEContext(ueCtx *ue_context.UEContext) {
	gnb.UEContext = ueCtx
}
