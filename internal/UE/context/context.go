package context

import (
	"github.com/free5gc/nas/nasType" //will change to reogac/nas later
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
	NgKSI            nasType.NoncurrentNativeNASKeySetIdentifier
	K_AMF            []byte
	K_NAS_int        []byte
	K_NAS_enc        []byte
	UplinkNASCount   uint32
	DownlinkNASCount uint32
}

type UEContext struct {
	Config           *UEConfig
	State            RegistrationState
	GUTI             *nasType.GUTI5G
	RegistrationArea []nasType.LastVisitedRegisteredTAI
	SecurityContext  UESecurityContext
}

func NewUEContext(cfg *UEConfig) *UEContext {
	ueCtx := &UEContext{
		Config: cfg,
		State:  Deregistered,
		SecurityContext: UESecurityContext{
			UplinkNASCount:   0,
			DownlinkNASCount: 0,
		},
	}

	ksi := nasType.NewNoncurrentNativeNASKeySetIdentifier(0)
	ksi.SetTsc(0)
	ksi.SetNasKeySetIdentifiler(7)
	ueCtx.SecurityContext.NgKSI = *ksi

	return ueCtx
}
