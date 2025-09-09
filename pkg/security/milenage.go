package security

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"log"
)

type Milenage struct {
	block   cipher.Block
	opc     [16]uint8
	randxor [16]uint8
	rand    [16]uint8
	reader  io.Reader
}

func NewMilenage(k []uint8, opopc []uint8, isopc bool) (m *Milenage, err error) {
	m, err = NewMilenageEx(k, rand.Reader, opopc, isopc)
	return
}

func NewMilenageEx(k []uint8, r io.Reader, opopc []uint8, isopc bool) (m *Milenage, err error) {
	if len(k) != 16 || len(opopc) != 16 {
		err = fmt.Errorf("wrong input size for Milenage keys")
		return
	}
	m = &Milenage{
		reader: r,
	}
	if r == nil {
		m.reader = rand.Reader
	}

	if m.block, err = aes.NewCipher(k); err != nil {
		return
	}

	if !isopc {
		m.block.Encrypt(m.opc[:], opopc)
		for i := 0; i < 16; i++ {
			m.opc[i] ^= opopc[i]
		}
	} else {
		copy(m.opc[:], opopc[:])
	}
	log.Printf("TRACE: [Milenage] Initialized with OPc: %x", m.opc)
	m.Refresh()
	return
}

func (m *Milenage) Refresh() {
	m.reader.Read(m.rand[:])
	var tmp [16]uint8
	for i := 0; i < 16; i++ {
		tmp[i] = m.rand[i] ^ m.opc[i]
	}
	m.block.Encrypt(m.randxor[:], tmp[:])
}

func (m *Milenage) SetRand(r []uint8) error {
	if len(r) != 16 {
		return fmt.Errorf("wrong rand size")
	}
	copy(m.rand[:], r)
	var tmp [16]uint8
	for i := 0; i < 16; i++ {
		tmp[i] = m.rand[i] ^ m.opc[i]
	}
	m.block.Encrypt(m.randxor[:], tmp[:])
	return nil
}

func (m *Milenage) GetRand() []uint8 {
	return m.rand[:]
}

func (m *Milenage) F1(sqn, amf []uint8) (maca []uint8, macs []uint8, err error) {
	if len(sqn) != 6 || len(amf) != 2 {
		err = fmt.Errorf("wrong size input for F1")
		return
	}
	var a, b, c [16]uint8
	copy(b[0:], sqn[:])
	copy(b[6:], amf[:])
	copy(b[8:], b[0:8])

	var j int
	for i := 0; i < 16; i++ {
		j = (i + 8) % 16
		c[j] = b[i] ^ m.opc[i] ^ m.randxor[j]
	}

	m.block.Encrypt(a[:], c[:])
	for i := 0; i < 16; i++ {
		a[i] ^= m.opc[i]
	}
	maca = a[0:8]
	macs = a[8:]
	return
}

func (m *Milenage) F2F5() ([]uint8, []uint8) {
	tmp := m.operation(0, 1)
	return tmp[8:16], tmp[:6]
}

func (m *Milenage) F3() []uint8 {
	return m.operation(12, 2)
}

func (m *Milenage) F4() []uint8 {
	return m.operation(8, 4)
}

func (m *Milenage) F5star() []uint8 {
	tmp := m.operation(4, 8)
	return tmp[:6]
}

func (m *Milenage) operation(rot int, v uint8) []uint8 {
	var a, b, c [16]uint8
	c[15] = v
	var j int
	for i := 0; i < 16; i++ {
		j = (i + rot) % 16
		a[j] = m.randxor[i] ^ m.opc[i] ^ c[j]
	}

	m.block.Encrypt(b[:], a[:])
	for i := 0; i < 16; i++ {
		b[i] ^= m.opc[i]
	}
	return b[:]
}

func (m *Milenage) ValidateAuts(auts, randv []byte) (sqn [6]uint8, err error) {
	if len(auts) != 14 || len(randv) != 16 {
		err = fmt.Errorf("wrong input size: auts[%d], rand[%d]", len(auts), len(randv))
		return
	}

	m.SetRand(randv)
	var amf [2]uint8
	ak_r := m.F5star()
	for i := 0; i < 6; i++ {
		sqn[i] = ak_r[i] ^ auts[i]
	}
	_, macs, _ := m.F1(sqn[:], amf[:])

	if !bytes.Equal(macs, auts[6:]) {
		err = fmt.Errorf("MAC failed: calculated MAC=%x, received MAC=%x", macs, auts[6:])
	}
	return
}
