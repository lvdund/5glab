package sec

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

type Milenage struct {
	block   cipher.Block
	opc     [16]uint8
	randxor [16]uint8
	rand    [16]uint8
	reader  io.Reader
}

func NewMilenage(k []uint8, opopc []uint8, isopc bool) (m *Milenage, err error) {
	return NewMilenageEx(k, rand.Reader, opopc, isopc)
}

func NewMilenageEx(k []uint8, r io.Reader, opopc []uint8, isopc bool) (m *Milenage, err error) {
	if len(k) != 16 || len(opopc) != 16 {
		err = fmt.Errorf("Wrong input size")
		return
	}
	m = &Milenage{reader: r}
	if r == nil {
		m.reader = rand.Reader
	}

	fmt.Printf("Milenage key=%x\n", k)

	if m.block, err = aes.NewCipher(k); err != nil {
		return
	}

	if !isopc {
		m.block.Encrypt(m.opc[:], opopc)
		for i := range 16 {
			m.opc[i] ^= opopc[i]
		}
	} else {
		copy(m.opc[:], opopc[:])
	}

	fmt.Printf("Milenage opc=%x\n", m.opc[:])
	m.Refresh()
	return
}

// prepare a new random vector
func (m *Milenage) Refresh() {
	m.reader.Read(m.rand[:])
	var tmp [16]uint8
	for i := range 16 {
		tmp[i] = m.rand[i] ^ m.opc[i]
	}
	m.block.Encrypt(m.randxor[:], tmp[:])
}

// set a new random vector
func (m *Milenage) SetRand(r []uint8) error {
	if len(r) != 16 {
		return fmt.Errorf("Wrong rand size")
	}
	copy(m.rand[:], r)
	var tmp [16]uint8
	for i := range 16 {
		tmp[i] = m.rand[i] ^ m.opc[i]
	}
	m.block.Encrypt(m.randxor[:], tmp[:])
	return nil
}

func (m *Milenage) GetRand() []uint8 { return m.rand[:] }

// f1 and f1star
func (m *Milenage) F1(sqn, amf []uint8) (maca []uint8, macs []uint8, err error) {
	if len(sqn) != 6 || len(amf) != 2 {
		err = fmt.Errorf("Wrong size input")
		return
	}
	var a, b, c [16]uint8
	copy(b[0:], sqn[:])
	copy(b[6:], amf[:])
	copy(b[8:], b[0:8])

	var j int
	for i := range 16 {
		j = (i + 8) % 16
		c[j] = b[i] ^ m.opc[i] ^ m.randxor[j]
	}

	m.block.Encrypt(a[:], c[:])
	for i := range 16 {
		a[i] ^= m.opc[i]
	}
	maca = a[0:8]
	macs = a[8:]
	return
}

func (m *Milenage) F2F5() ([]uint8, []uint8) {
	tmp := m.operation(0, 1)
	return tmp[8:16], tmp[:6] // res, ak
}
func (m *Milenage) F3() []uint8        { return m.operation(12, 2) } // ck
func (m *Milenage) F4() []uint8        { return m.operation(8, 4) }  // ik
func (m *Milenage) F5star() []uint8    { tmp := m.operation(4, 8); return tmp[:6] }
func (m *Milenage) operation(rot int, v uint8) []uint8 {
	var a, b, c [16]uint8
	c[15] = v
	var j int
	for i := range 16 {
		j = (i + rot) % 16
		a[j] = m.randxor[i] ^ m.opc[i] ^ c[j]
	}
	m.block.Encrypt(b[:], a[:])
	for i := range 16 {
		b[i] ^= m.opc[i]
	}
	return b[:]
}

func (m *Milenage) ValidateAuts(auts, randv []byte) (sqn [6]uint8, err error) {
	// accept AUTN length 14 (no AMF) or 16 (with AMF)
	if !(len(auts) == 14 || len(auts) == 16) || len(randv) != 16 {
		err = fmt.Errorf("Wrong input size: auts[%d], rand[%d]", len(auts), len(randv))
		return
	}

	
	if setErr := m.SetRand(randv); setErr != nil {
		err = fmt.Errorf("SetRand failed: %v", setErr)
		return
	}

	
	var sqnXorAk []byte
	var amfBytes [2]uint8
	var macReceived []byte

	if len(auts) == 16 {
		sqnXorAk = auts[0:6]
		amfBytes[0] = auts[6]
		amfBytes[1] = auts[7]
		macReceived = auts[8:16]
	} else { // 14 bytes
		sqnXorAk = auts[0:6]
		amfBytes[0] = 0x80
		amfBytes[1] = 0x00
		macReceived = auts[6:14]
	}

	
	ak_r := m.F5star()

	
	for i := range 6 {
		sqn[i] = ak_r[i] ^ sqnXorAk[i]
	}

	
amfSlice := []uint8{amfBytes[0], amfBytes[1]}
_, macs, ferr := m.F1(sqn[:], amfSlice)
	if ferr != nil {
		err = fmt.Errorf("F1 failed: %v", ferr)
		return
	}

	
	// Debug prints
	fmt.Printf("[Milenage DEBUG] rand=%x\n", m.rand)
	fmt.Printf("[Milenage DEBUG] opc=%x\n", m.opc[:])
	fmt.Printf("[Milenage DEBUG] SQN^AK=%x\n", sqnXorAk)
	fmt.Printf("[Milenage DEBUG] AK=%x\n", ak_r)
	fmt.Printf("[Milenage DEBUG] SQN=%x\n", sqn)
	fmt.Printf("[Milenage DEBUG] AMF=%x\n", amfBytes)
	fmt.Printf("[Milenage DEBUG] MAC_calc=%x\n", macs)
	fmt.Printf("[Milenage DEBUG] MAC_recv=%x\n", macReceived)

	if !bytes.Equal(macs, macReceived) {
		err = fmt.Errorf("MAC failed: calculated MAC=%x, received MAC=%x", macs, macReceived)
	}
	return
}
