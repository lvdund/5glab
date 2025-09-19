package context

import (
	"5g-emulator/pkg/security"
	"bytes"

	"github.com/reogac/nas"
)

const (
	AUTH_SUCCESS uint8 = iota
	AUTH_MAC_FAILURE
	AUTH_SYNC_FAILURE
)

type AuthContext struct {
	Supi     string
	Snn      []byte
	Kamf     []byte
	Rand     []byte
	NgKsi    nas.KeySetIdentifier
	Sqn      security.Sqn
	Amf      []byte
	Milenage *security.Milenage
}

func (auth *AuthContext) ProcessAuthenticationInfo(autn, abba []byte) (errCode uint8, output []byte) {
	ueSqn := auth.Sqn.Bytes()

	// 1. Generate RES, CK, IK, AK
	res, ak := auth.Milenage.F2F5()
	ck := auth.Milenage.F3()
	ik := auth.Milenage.F4()
	key := append(ck, ik...)

	//2.derive netSqn, netMacA from autn
	netSqn := make([]byte, 6)
	//netAmf := autn[6:8]
	sqnXorAk := autn[0:6]
	netMacA := autn[8:]
	for i := range 6 {
		netSqn[i] = sqnXorAk[i] ^ ak[i]
	}

	//3. calculate MacA and verify
	macA, _, _ := auth.Milenage.F1(netSqn, auth.Amf)
	if !bytes.Equal(macA, netMacA) {
		errCode = AUTH_MAC_FAILURE
		return
	}

	//4. check for sqn sync
	tmpSqn := new(security.Sqn)
	tmpSqn.Set(netSqn)                                 //calculate net sqn in int64
	syncFailure := auth.Sqn.GetVal() > tmpSqn.GetVal() //ue's sqn is greater than network's sqn
	if syncFailure {
		//4.1 prepare auts
		amfSync := []byte{0, 0} //resync AMF
		akStar := auth.Milenage.F5star()
		// get mac_s using sqn ue.
		_, macS, _ := auth.Milenage.F1(ueSqn, amfSync)

		sqnXorAk = make([]byte, 6)
		for i := range ueSqn {
			sqnXorAk[i] = ueSqn[i] ^ akStar[i]
		}

		output = append(sqnXorAk, macS...)
		errCode = AUTH_SYNC_FAILURE
		return
	}
	//update SQN from network
	auth.Sqn.Set(netSqn)

	//5. derive KAMF
	//5.1 derive KAUSF
	sqnXorAk = make([]byte, 6)
	for i := range netSqn {
		sqnXorAk[i] = netSqn[i] ^ ak[i]
	}
	kAusf, _ := security.KAUSF(key, auth.Snn, sqnXorAk)

	//5.2 derive KSEAF
	kSeaf, _ := security.SeafKey(kAusf, auth.Snn)
	//5.3 derive KAMF
	auth.Kamf, _ = security.KAMF(kSeaf, []byte(auth.Supi[5:]), abba)

	//6. prepare resStar
	_, output, _ = security.ResstarXresstar(key, auth.Snn, auth.Rand, res)
	return
}

func deriveSNN(mcc, mnc string) string {
	// 5G:mnc093.mcc208.3gppnetwork.org
	var resu string
	if len(mnc) == 2 {
		resu = "5G:mnc0" + mnc + ".mcc" + mcc + ".3gppnetwork.org"
	} else {
		resu = "5G:mnc" + mnc + ".mcc" + mcc + ".3gppnetwork.org"
	}
	return resu
}
