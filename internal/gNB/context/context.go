package context

import (
	ue_context "5g-emulator/internal/UE/context"

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
	Config      *GNBConfig
	SCTPConn    *sctp.SCTPConn
	UEContext   *ue_context.UEContext
	AmfUeNgapID int64
	RanUeNgapID int64
}

func NewGNBContext(cfg *GNBConfig, conn *sctp.SCTPConn) *GNBContext {
	return &GNBContext{
		Config:      cfg,
		SCTPConn:    conn,
		RanUeNgapID: 1,
	}
}

func (gnb *GNBContext) SetUEContext(ueCtx *ue_context.UEContext) {
	gnb.UEContext = ueCtx
}
