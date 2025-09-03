package context

import (
	"github.com/reogac/nas"
)

type RegistrationState int

const (
	Deregistered RegistrationState = iota
	Registering
	Registered
)

type UEConfig struct {
	IMSI string `yaml:"imsi"`
	Key  string `yaml:"key"`
	OPc  string `yaml:"opc"`
	AMF  string `yaml:"amf"`
}

type UESecurityContext struct {
	NgKSI            nas.KeySetIdentifier
	K_AMF            []byte
	K_NAS_int        []byte
	K_NAS_enc        []byte
	UplinkNASCount   uint32
	DownlinkNASCount uint32
}

type UEContext struct {
	Config           *UEConfig
	State            RegistrationState
	GUTI             *nas.Guti
	RegistrationArea []nas.TrackingAreaIdentity
	SecurityContext  UESecurityContext
}

func NewUEContext(cfg *UEConfig) *UEContext {
	return &UEContext{
		Config: cfg,
		State:  Deregistered,
		SecurityContext: UESecurityContext{
			NgKSI: nas.KeySetIdentifier{
				Tsc: 0,
				Id:  7,
			},
			UplinkNASCount:   0,
			DownlinkNASCount: 0,
		},
	}
}
