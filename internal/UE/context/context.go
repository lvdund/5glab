package context

import (
	"5g-emulator/internal/radio"
	"5g-emulator/pkg/security"
	"crypto/aes"
	"encoding/hex"
	"errors"
	"fmt"

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
	OP   string `yaml:"op"`
	AMF  string `yaml:"amf"`
}

type UESecurityContext struct {
	NgKSI            nas.KeySetIdentifier
	Kamf             []byte
	UplinkNASCount   uint32
	DownlinkNASCount uint32
	Sqn              security.Sqn
}

type UEContext struct {
	Config *UEConfig
	State  RegistrationState
	GUTI   *nas.Guti

	k    []byte
	opc  []byte
	supi string
	mcc  string
	mnc  string

	RegistrationArea []nas.TrackingAreaIdentity
	SecurityContext  UESecurityContext
	Radio            *radio.RadioLink
}

func NewUEContext(cfg *UEConfig, radioLink *radio.RadioLink) (*UEContext, error) {
	if len(cfg.Key) != 32 || len(cfg.OP) != 32 {
		return nil, errors.New("configuration error: Key and OP must be 32-character hex strings (16 bytes)")
	}
	k, err := hex.DecodeString(cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Key: %w", err)
	}
	op, err := hex.DecodeString(cfg.OP)
	if err != nil {
		return nil, fmt.Errorf("failed to decode OP: %w", err)
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher for OPc calculation: %w", err)
	}
	opc := make([]byte, 16)
	block.Encrypt(opc, op)
	for i := 0; i < 16; i++ {
		opc[i] ^= op[i]
	}
	supi := "imsi-" + cfg.IMSI
	mcc := cfg.IMSI[0:3]

	mnc := cfg.IMSI[3:6]
	if len(cfg.IMSI) == 14 {
		mnc = "0" + cfg.IMSI[3:5]
	}

	ctx := &UEContext{
		Config: cfg,
		State:  Deregistered,
		Radio:  radioLink,
		k:      k,
		opc:    opc,
		supi:   supi,
		mcc:    mcc,
		mnc:    mnc,

		SecurityContext: UESecurityContext{
			NgKSI: nas.KeySetIdentifier{
				Tsc: 0,
				Id:  7,
			},
			UplinkNASCount:   0,
			DownlinkNASCount: 0,
			Sqn:              security.Sqn{},
		},
	}
	return ctx, nil
}

func (c *UEContext) K() []byte {
	return c.k
}

func (c *UEContext) Opc() []byte {
	return c.opc
}

func (c *UEContext) Supi() string {
	return c.supi
}

func (c *UEContext) Mcc() string {
	return c.mcc
}

func (c *UEContext) Mnc() string {
	return c.mnc
}

func (c *UEContext) GetSqn() *security.Sqn {
	return &c.SecurityContext.Sqn
}

func (c *UEContext) SetSqn(sqn []byte) {
	c.SecurityContext.Sqn.Set(sqn)
}
