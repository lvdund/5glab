package context

import (
	"5g-emulator/internal/radio"
	"5g-emulator/pkg/security"
	"crypto/aes"
	"encoding/hex"
	"errors"
	"fmt"
	"log"

	"github.com/reogac/nas"
)

type RegistrationState int

const (
	Deregistered RegistrationState = iota
	Registering
	Registered
)

type UEConfig struct {
	IMSI   string `yaml:"imsi"`
	Key    string `yaml:"key"`
	OP     string `yaml:"op"`
	OpType string `yaml:"opType"`
	AMF    string `yaml:"amf"`
	SQN    string `yaml:"sqn"`
}

type UESecurityContext struct {
	NgKSI            nas.KeySetIdentifier
	Kamf             []byte
	UplinkNASCount   uint32
	DownlinkNASCount uint32
	Sqn              security.Sqn
	NasContext       *nas.NasContext
	CipheringAlg     uint8
	IntegrityAlg     uint8
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

	Auth AuthContext

	RegistrationArea []nas.TrackingAreaIdentity
	SecurityContext  *security.SecurityContext
	Radio            *radio.RadioLink
}

func NewUEContext(cfg *UEConfig, mcc string, mnc string, radioLink *radio.RadioLink) (*UEContext, error) {
	var ctx *UEContext

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

	log.Printf("DEBUG: [UE Context] Loaded config: IMSI=%s, Key=%s, OP=%s, OpType='%s'", cfg.IMSI, cfg.Key, cfg.OP, cfg.OpType)

	var opc []byte
	if cfg.OpType == "OPC" {
		opc = op
		log.Printf("DEBUG: [UE Context] Using provided value as OPc: %x", opc)

	} else {
		log.Printf("DEBUG: [UE Context] Calculating OPc from OP...")
		block, err := aes.NewCipher(k)
		if err != nil {
			return nil, fmt.Errorf("failed to create cipher for OPc calculation: %w", err)
		}
		opc = make([]byte, 16)
		block.Encrypt(opc, op)
		for i := 0; i < 16; i++ {
			opc[i] ^= op[i]
		}
		log.Printf("DEBUG: [UE Context] Calculated OPc: %x", opc)
	}

	var authCtx AuthContext

	key, _ := hex.DecodeString(cfg.Key)
	op, _ = hex.DecodeString(cfg.OP)
	milenage, _ := security.NewMilenage(key, op, true) //use OPC
	authCtx.Milenage = milenage

	amf, _ := hex.DecodeString(cfg.AMF)
	sqn, _ := hex.DecodeString(cfg.SQN)
	authCtx.Amf = amf
	authCtx.Sqn.Set(sqn)

	authCtx.Supi = fmt.Sprintf("imsi-%s%s%s", mcc, mnc, cfg.IMSI[5:])

	supi := "imsi-" + cfg.IMSI

	// if len(mnc) == 2 {
	// 	mnc = "0" + mnc
	// }

	ctx = &UEContext{
		Config: cfg,
		State:  Deregistered,
		Radio:  radioLink,
		k:      k,
		opc:    opc,
		supi:   supi,
		mcc:    mcc,
		mnc:    mnc,
		Auth:   authCtx,
		// SecurityContext: UESecurityContext{
		// 	NgKSI: nas.KeySetIdentifier{
		// 		Tsc: 0,
		// 		Id:  7,
		// 	},
		// 	UplinkNASCount:   0,
		// 	DownlinkNASCount: 0,
		// 	Sqn:              security.Sqn{},
		// 	NasContext:       nas.NewNasContext(false),
		// },
	}
	return ctx, nil
}

func (c *UEContext) ActivateNasSecurity(encAlg, intAlg uint8) error {
	// if c.SecurityContext.Kamf == nil {
	// 	return errors.New("cannot activate NAS security without Kamf")
	// }
	//
	// err := c.SecurityContext.NasContext.DeriveKeys(intAlg, encAlg, c.SecurityContext.Kamf)
	// if err != nil {
	// 	return fmt.Errorf("failed to derive NAS keys in nas context: %w", err)
	// }
	//
	// c.SecurityContext.UplinkNASCount = 0
	// c.SecurityContext.DownlinkNASCount = 0

	log.Println("INFO: [UE Context] NAS security keys derived and context activated.")
	return nil
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
	return &c.Auth.Sqn
}

func (c *UEContext) SetSqn(sqn []byte) {
	c.Auth.Sqn.Set(sqn)
}
