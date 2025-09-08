package uecontext

import (
	"bytes"
	"fmt" 
	"emulator/internal/uecontext/sec"

	"github.com/reogac/nas"
)

const (
	AUTH_SUCCESS uint8 = iota
	AUTH_MAC_FAILURE
	AUTH_SYNC_FAILURE
)

type AuthContext struct {
	supi     string
	snn      []byte
	kamf     []byte
	rand     []byte
	ngKsi    nas.KeySetIdentifier
	sqn      sec.Sqn
	amf      []byte
	milenage *sec.Milenage
	xresStar []byte
}

func (auth *AuthContext) ProcessAuthenticationInfo(autn, abba []byte) (errCode uint8, output []byte) {
	if len(autn) < 14 {
		fmt.Printf("[ERROR] AUTN too short: len=%d\n", len(autn))
		errCode = AUTH_MAC_FAILURE
		return
	}

	// Get the current SQN of the UE (format []byte)
	ueSqn := auth.sqn.Bytes()

	// Load RAND into milenage before calling F2/F3/F4/F1
	if auth.milenage != nil {
		if err := auth.milenage.SetRand(auth.rand); err != nil {
			fmt.Printf("[WARN] milenage.SetRand returned error: %v\n", err)
		}
		if getter, ok := interface{}(auth.milenage).(interface{ GetRand() []byte }); ok {
			fmt.Printf("[DEBUG] RAND inside milenage: %x\n", getter.GetRand())
		}
	}

	// 1. Generate RES, CK, IK, AK 
	res, ak := auth.milenage.F2F5()
	ck := auth.milenage.F3()
	ik := auth.milenage.F4()
	key := append(ck, ik...)

	// 2. derive netSqn, netMacA from autn
	netSqn := make([]byte, 6)
	sqnXorAk := autn[0:6]
	netMacA := autn[8:]
	for i := 0; i < len(netSqn) && i < len(ak); i++ {
		netSqn[i] = sqnXorAk[i] ^ ak[i]
	}
	
	// 3. calculate MacA and verify
	macA, _, _ := auth.milenage.F1(netSqn, auth.amf)

	fmt.Printf("[DEBUG] RAND used (auth.rand): %x\n", auth.rand)
	fmt.Printf("[DEBUG] UE SQN (before AUTN): %x\n", ueSqn)
	fmt.Printf("[DEBUG] Network SQN (decoded): %x\n", netSqn)
	fmt.Printf("[DEBUG] MAC-A (from network AUTN): %x\n", netMacA)
	fmt.Printf("[DEBUG] MAC-A (calculated by UE): %x\n", macA)

	if !bytes.Equal(macA, netMacA) {
		fmt.Println("[WARN] MAC verification failed → prepare AUTS (resync)")

		amfSync := []byte{0, 0}
		akStar := auth.milenage.F5star()
		_, macS, _ := auth.milenage.F1(ueSqn, amfSync)

		sqnXorAkResync := make([]byte, 6)
		for i := 0; i < len(sqnXorAkResync) && i < len(ueSqn) && i < len(akStar); i++ {
			sqnXorAkResync[i] = ueSqn[i] ^ akStar[i]
		}

		output = append(sqnXorAkResync, macS...)
		errCode = AUTH_SYNC_FAILURE
		return
	}
	fmt.Println("[INFO] MAC verification passed")

	// 4. check for sqn sync
	tmpSqn := new(sec.Sqn)
	tmpSqn.Set(netSqn)
	syncFailure := auth.sqn.GetVal() > tmpSqn.GetVal()
	if syncFailure {
		fmt.Println("[WARN] SQN sync failure detected, sending AUTS")

		amfSync := []byte{0, 0}
		akStar := auth.milenage.F5star()
		_, macS, _ := auth.milenage.F1(ueSqn, amfSync)

		sqnXorAkResync := make([]byte, 6)
		for i := 0; i < len(sqnXorAkResync) && i < len(ueSqn) && i < len(akStar); i++ {
			sqnXorAkResync[i] = ueSqn[i] ^ akStar[i]
		}

		output = append(sqnXorAkResync, macS...)
		errCode = AUTH_SYNC_FAILURE
		return
	}

	auth.sqn.Set(netSqn)

	// 5. derive KAMF
	sqnXorAk = make([]byte, 6)
	for i := 0; i < len(sqnXorAk) && i < len(netSqn) && i < len(ak); i++ {
		sqnXorAk[i] = netSqn[i] ^ ak[i]
	}
	kAusf, _ := sec.KAUSF(key, auth.snn, sqnXorAk)
	kSeaf, _ := sec.SeafKey(kAusf, auth.snn)
	auth.kamf, _ = sec.KAMF(kSeaf, []byte(auth.supi[5:]), abba)

	// 6. prepare resStar
	_, output, _ = sec.ResstarXresstar(key, auth.snn, auth.rand, res)   
	//resstar, _, _ := sec.ResstarXresstar(key, auth.snn, auth.rand, res)   //8/9/2025
	//output = resstar   

	errCode = AUTH_SUCCESS
	// auth.sqn.Increment()  
	return
}
