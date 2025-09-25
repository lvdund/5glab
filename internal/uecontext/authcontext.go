package uecontext

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"strconv"

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

func printHex(label string, data []byte) {
	/*if data != nil {
		fmt.Printf("[DBG] %s: %x\n", label, data)
	} else {
		fmt.Printf("[DBG] %s: <nil>\n", label)
	}*/
}

// buildServingNetworkFromSNN converts auth.snn like "20893" or "208093" ->
// "5G:mnc093.mcc208.3gppnetwork.org" as required by 3GPP SN-name representation.
func buildServingNetworkFromSNN(snn []byte) string {
	if snn == nil || len(snn) == 0 {
		return ""
	}
	s := string(snn) // expect something like "20893" or "208093"
	if len(s) < 4 {
		return ""
	}
	mcc := s[:3]
	mnc := s[3:]
	// pad MNC to 3 digits if needed
	if len(mnc) == 2 {
		mnc = "0" + mnc
	} else if len(mnc) == 1 {
		mnc = "00" + mnc
	} else if len(mnc) > 3 {
		// fallback: parse numeric and format
		if n, err := strconv.Atoi(mnc); err == nil {
			mnc = fmt.Sprintf("%03d", n)
		} else {
			mnc = mnc[:3]
		}
	}
	return fmt.Sprintf("5G:mnc%v.mcc%v.3gppnetwork.org", mnc, mcc)
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
	key := append(ck, ik...) // CK||IK

	/*
	// Debug logs
	printHex("RAND (auth.rand)", auth.rand)
	printHex("RES (Milenage)", res)
	printHex("CK", ck)
	printHex("IK", ik)
	printHex("CK||IK (K for KDF)", key)
	printHex("AK", ak)*/

	// 2. derive netSqn, netMacA from autn
	netSqn := make([]byte, 6)
	sqnXorAk := autn[0:6]
	netMacA := autn[8:]
	for i := 0; i < len(netSqn) && i < len(ak); i++ {
		netSqn[i] = sqnXorAk[i] ^ ak[i]
	}

	// 3. calculate MacA and verify
	macA, _, _ := auth.milenage.F1(netSqn, auth.amf)

	
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

	// --- Extra logs to debug RES*/XRES*/HRES* mismatch ---
	// Build proper Serving Network string and bytes for KDF (3GPP format)
	servingNetStr := buildServingNetworkFromSNN(auth.snn)
	servingNetBytes := []byte(servingNetStr)

	/*printHex("auth.snn (raw)", auth.snn)
	fmt.Printf("[DBG] Serving Network (derived string): %s\n", servingNetStr)
	printHex("Serving Network (bytes for KDF)", servingNetBytes)
	printHex("ABBA (from network)", abba)*/

	// 6. prepare resStar / xresStar
	// Note: sec.ResstarXresstar currently expects (key, servingnet, rand, res)
	// so pass servingNetBytes as the servingnet argument
	resstar, xresstar, err := sec.ResstarXresstar(key, servingNetBytes, auth.rand, res)
	if err != nil {
		// If KDF failed, log and return MAC failure to avoid confusing state.
		fmt.Printf("[ERROR] ResstarXresstar KDF error: %v\n", err)
		errCode = AUTH_MAC_FAILURE
		return
	}
	printHex("RES*", resstar)
	printHex("XRES*", xresstar)

	// HRES* = SHA256(RAND||XRES*)
	h := sha256.New()
	h.Write(auth.rand)
	h.Write(xresstar)
	hresstar := h.Sum(nil)
	printHex("HRES* (full SHA256)", hresstar)
	//fmt.Printf("[DBG] HRES* (truncated 16B - first16): %x\n", hresstar[:16])
	//fmt.Printf("[DBG] HRES* (truncated 16B - last16) : %x\n", hresstar[16:])

	// store xresStar for potential later checks
	auth.xresStar = xresstar

	// 7. prepare output (RES* to send to AMF)
	output = resstar
	errCode = AUTH_SUCCESS
	return
}

