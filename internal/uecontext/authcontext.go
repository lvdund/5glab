package uecontext

import (
	"bytes"
	"fmt"
	"regexp"
	//"strconv"

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

func kdfPreimage(fc byte, p0 []byte, p1 []byte) []byte {
	// FC || L0(2B big-endian) || P0 || L1(2B) || P1
	b := []byte{fc}
	l0 := len(p0)
	b = append(b, byte((l0>>8)&0xff), byte(l0&0xff))
	b = append(b, p0...)
	l1 := len(p1)
	b = append(b, byte((l1>>8)&0xff), byte(l1&0xff))
	b = append(b, p1...)
	return b
}


func (auth *AuthContext) ProcessAuthenticationInfo(autn, abba []byte) (errCode uint8, output []byte) {
    if len(autn) < 14 {
        fmt.Printf("[ERROR] AUTN too short: len=%d\n", len(autn))
        errCode = AUTH_MAC_FAILURE
        return
    }

    ueSqn := auth.sqn.Bytes()

    if auth.milenage != nil {
        if err := auth.milenage.SetRand(auth.rand); err != nil {
            fmt.Printf("[WARN] milenage.SetRand returned error: %v\n", err)
        }
        if getter, ok := interface{}(auth.milenage).(interface{ GetRand() []byte }); ok {
            fmt.Printf("[DEBUG] RAND inside milenage: %x\n", getter.GetRand())
        }
    }

    res, ak := auth.milenage.F2F5()
    ck := auth.milenage.F3()
    ik := auth.milenage.F4()
    key := append(ck, ik...)

    fmt.Printf("[DEBUG] UE RAND: %x\n", auth.rand)
    fmt.Printf("[DEBUG] RES (F2F5): %x\n", res)
    fmt.Printf("[DEBUG] CK: %x\n", ck)
    fmt.Printf("[DEBUG] IK: %x\n", ik)
    fmt.Printf("[DEBUG] AK: %x\n", ak)
    fmt.Printf("[DEBUG] CK||IK (K for KDF): %x\n", key)
    fmt.Printf("[DEBUG] AUTN: %x\n", autn)
    fmt.Printf("[DEBUG] UE SQN (before AUTN): %x\n", ueSqn)

    // Decode network SQN from AUTN
    netSqn := make([]byte, 6)
    sqnXorAk := autn[0:6]
    netMacA := autn[8:]
    for i := 0; i < len(netSqn) && i < len(ak); i++ {
        netSqn[i] = sqnXorAk[i] ^ ak[i]
    }

    macA, _, _ := auth.milenage.F1(netSqn, auth.amf)
    fmt.Printf("[DEBUG] Network SQN (decoded): %x\n", netSqn)
    fmt.Printf("[DEBUG] SQN⊕AK (from AUTN): %x\n", sqnXorAk)
    fmt.Printf("[DEBUG] MAC-A (from network AUTN): %x\n", netMacA)
    fmt.Printf("[DEBUG] MAC-A (calculated by UE): %x\n", macA)

    if !bytes.Equal(macA, netMacA) {
        fmt.Println("[WARN] MAC verification failed → prepare AUTS (resync)")
        errCode = AUTH_MAC_FAILURE
        return
    }
    fmt.Println("[INFO] MAC verification passed")

    
    //fmt.Println("========== TESTING BOTH KAUSF DERIVATION METHODS ==========")
    
    // Method 1: Use SQN⊕AK (from AUTN directly)
    servingNetStr1 := buildServingNetworkFromSNN(auth.snn)
    servingNetBytes1 := []byte(servingNetStr1)
    
    kAusf1, _ := sec.KAUSF(key, servingNetBytes1, sqnXorAk)  // Use SQN⊕AK
    kSeaf1, _ := sec.SeafKey(kAusf1, servingNetBytes1)
    
    // fmt.Printf("[METHOD 1] Serving Network: %s\n", servingNetStr1)
    // fmt.Printf("[METHOD 1] Using SQN⊕AK: %x\n", sqnXorAk)
    // fmt.Printf("[METHOD 1] KAUSF: %x\n", kAusf1)
    // fmt.Printf("[METHOD 1] KSEAF: %x\n", kSeaf1)
    
    // Method 2: Use decoded SQN
    //kAusf2, _ := sec.KAUSF(key, servingNetBytes1, netSqn)    // Use decoded SQN
    //kSeaf2, _ := sec.SeafKey(kAusf2, servingNetBytes1)
    
    // fmt.Printf("[METHOD 2] Using decoded SQN: %x\n", netSqn)
    // fmt.Printf("[METHOD 2] KAUSF: %x\n", kAusf2)
    // fmt.Printf("[METHOD 2] KSEAF: %x\n", kSeaf2)

    // Try different serving network formats
    //servingNetStr2 := fmt.Sprintf("5G:mnc%s.mcc%s.3gppnetwork.org", 
    //    string(auth.snn[3:]), string(auth.snn[:3]))
    //servingNetBytes2 := []byte(servingNetStr2)
    
    //kAusf3, _ := sec.KAUSF(key, servingNetBytes2, sqnXorAk)
    //kSeaf3, _ := sec.SeafKey(kAusf3, servingNetBytes2)
    
    // fmt.Printf("[METHOD 3] Alternative serving network: %s\n", servingNetStr2)
    // fmt.Printf("[METHOD 3] KAUSF: %x\n", kAusf3)
    // fmt.Printf("[METHOD 3] KSEAF: %x\n", kSeaf3)
    
    // Try with raw SNN directly
    //kAusf4, _ := sec.KAUSF(key, auth.snn, sqnXorAk)
    //kSeaf4, _ := sec.SeafKey(kAusf4, auth.snn)
    
    // fmt.Printf("[METHOD 4] Using raw SNN: %s (%x)\n", string(auth.snn), auth.snn)
    // fmt.Printf("[METHOD 4] KAUSF: %x\n", kAusf4)
    // fmt.Printf("[METHOD 4] KSEAF: %x\n", kSeaf4)
    
    fmt.Println("============================================================")

    // Extract SUPI components
    re := regexp.MustCompile("(?:imsi|supi)-([0-9]{5,15})")
    groups := re.FindStringSubmatch(auth.supi)
    if groups == nil {
        fmt.Printf("[ERROR] Could not extract IMSI from SUPI: %s\n", auth.supi)
        errCode = AUTH_MAC_FAILURE
        return
    }
    
    imsiOnly := []byte(groups[1])
    fmt.Printf("[DEBUG] SUPI raw: %s\n", auth.supi)
    fmt.Printf("[DEBUG] IMSI only (P0): %s\n", string(imsiOnly))
    fmt.Printf("[DEBUG] ABBA (P1): %x\n", abba)
    
    // Derive KAMF using all methods
    //fmt.Println("========== KAMF DERIVATION COMPARISON ==========")
    
    kamf1, _ := sec.KAMF(kSeaf1, imsiOnly, abba)
    //fmt.Printf("[KAMF METHOD 1] (SQN⊕AK + standard SNN): %x\n", kamf1)
    
    //kamf2, _ := sec.KAMF(kSeaf2, imsiOnly, abba)
    //fmt.Printf("[KAMF METHOD 2] (decoded SQN + standard SNN): %x\n", kamf2)
    
    //kamf3, _ := sec.KAMF(kSeaf3, imsiOnly, abba)
    //fmt.Printf("[KAMF METHOD 3] (SQN⊕AK + alt SNN): %x\n", kamf3)
    
    //kamf4, _ := sec.KAMF(kSeaf4, imsiOnly, abba)
   // fmt.Printf("[KAMF METHOD 4] (SQN⊕AK + raw SNN): %x\n", kamf4)
    
    
    // Choose the method that matches AMF (you'll need to check logs)
    // For now, let's try Method 1
    auth.kamf = kamf1
    
    preimage := kdfPreimage(0x6D, imsiOnly, abba)
    fmt.Printf("[DEBUG] KDF Preimage: %x\n", preimage)
    
    fmt.Println("===============================================")

    // Compute RES* and XRES*
    resstar, xresstar, err := sec.ResstarXresstar(key, servingNetBytes1, auth.rand, res)
    if err != nil {
        fmt.Printf("[ERROR] ResstarXresstar KDF error: %v\n", err)
        errCode = AUTH_MAC_FAILURE
        return
    }
    fmt.Printf("[DEBUG] RES*: %x\n", resstar)
    fmt.Printf("[DEBUG] XRES*: %x\n", xresstar)

    auth.xresStar = xresstar
    output = resstar
    errCode = AUTH_SUCCESS
    return
}

// Improved serving network builder với nhiều format
func buildServingNetworkFromSNN(snn []byte) string {
    if snn == nil || len(snn) == 0 {
        return "5G:mnc093.mcc208.3gppnetwork.org"
    }
    
    s := string(snn)
    fmt.Printf("[DEBUG] Raw SNN: %s (bytes: %x)\n", s, snn)
    
    if len(s) < 4 {
        return "5G:mnc093.mcc208.3gppnetwork.org"
    }
    
    // Assume format is MCCMNC (e.g., "20893")
    mcc := s[:3]   // "208"
    mnc := s[3:]   // "93"
    
    // Pad MNC to 3 digits
    if len(mnc) == 2 {
        mnc = "0" + mnc
    } else if len(mnc) == 1 {
        mnc = "00" + mnc
    }
    
    result := fmt.Sprintf("5G:mnc%s.mcc%s.3gppnetwork.org", mnc, mcc)
    fmt.Printf("[DEBUG] Built serving network: %s\n", result)
    return result
}