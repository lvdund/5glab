package security

import (
	"bytes"
	"errors"
	"fmt"
	"log"
)

type SecurityResult struct {
	KAMF     []byte
	RES_star []byte
}

func HandleAuthenticationChallenge(ueAuth UEAndNetworkAuth, rand []byte, autn []byte) (*SecurityResult, error) {
	if len(rand) != 16 || len(autn) != 16 {
		return nil, errors.New("invalid RAND or AUTN length")
	}

	m, err := NewMilenage(ueAuth.K(), ueAuth.Opc(), true)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize milenage: %v", err)
	}

	if err := m.SetRand(rand); err != nil {
		return nil, fmt.Errorf("failed to set rand for milenage: %v", err)
	}

	sqnXorAk := autn[0:6]
	amf := autn[6:8]
	macA := autn[8:16]

	res, ak := m.F2F5()
	ck := m.F3()
	ik := m.F4()

	sqnBytes := make([]byte, 6)
	for i := 0; i < 6; i++ {
		sqnBytes[i] = sqnXorAk[i] ^ ak[i]
	}

	receivedSqn := new(Sqn)
	receivedSqn.Set(sqnBytes)
	if receivedSqn.GetVal() <= ueAuth.GetSqn().GetVal() {
		return nil, fmt.Errorf("SQN verification failed: received SQN (%d) is not fresh, expected > %d",
			receivedSqn.GetVal(), ueAuth.GetSqn().GetVal())
	}

	xMacA, _, err := m.F1(sqnBytes, amf)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate F1 (XMAC-A): %v", err)
	}

	if !bytes.Equal(macA, xMacA) {
		return nil, errors.New("MAC verification failed: network authenticity compromised")
	}

	log.Println("INFO: [UE Security] AUTN verification successful.")

	ckik := append(ck, ik...)

	snn := fmt.Sprintf("5G:mnc%s.mcc%s.3gppnetwork.org", ueAuth.Mnc(), ueAuth.Mcc())

	resStar, _, err := ResstarXresstar(ckik, []byte(snn), rand, res)
	if err != nil {
		return nil, fmt.Errorf("failed to derive RES*: %v", err)
	}

	kausf, err := KAUSF(ckik, []byte(snn), sqnXorAk)
	if err != nil {
		return nil, fmt.Errorf("failed to derive KAUSF: %v", err)
	}

	kseaf, err := SeafKey(kausf, []byte(snn))
	if err != nil {
		return nil, fmt.Errorf("failed to derive KSEAF: %v", err)
	}

	supiBytes := []byte(ueAuth.Supi())
	abba := []byte{0x00, 0x00}
	kamf, err := KAMF(kseaf, supiBytes, abba)
	if err != nil {
		return nil, fmt.Errorf("failed to derive KAMF: %v", err)
	}

	ueAuth.SetSqn(sqnBytes)

	log.Printf("INFO: [UE Security] Derived KAMF: %x", kamf)

	return &SecurityResult{
		KAMF:     kamf,
		RES_star: resStar,
	}, nil
}
