package sctp

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/ishidawataru/sctp"
)

type SctpConn struct {
	localAddr, amfAddr string
	amfPort            int
	conn               *sctp.SCTPConn
}

func NewSctpConn(addr string, port int) *SctpConn {
	// SCTP connect to AMF
	var conn *sctp.SCTPConn
	var err error
	for i := range 3 { // retry 3 times
		conn, err = connectToAmf(addr, port)
		if err != nil {
			fmt.Printf("Attempt %d: SCTP connection failed: %v\n", i+1, err)
			time.Sleep(1 * time.Second)
			continue
		}
		break
	}
	if conn == nil {
		return nil
	}

	return &SctpConn{
		amfAddr: addr,
		amfPort: port,
		conn:    conn,
	}
}

func connectToAmf(amfIP string, amfPort int) (*sctp.SCTPConn, error) {
	addr := &sctp.SCTPAddr{
		IPAddrs: []net.IPAddr{
			{IP: net.ParseIP(amfIP)},
		},
		Port: amfPort,
	}
	init := sctp.InitMsg{
		NumOstreams:    10,
		MaxInstreams:   10,
		MaxAttempts:    4,
		MaxInitTimeout: 60,
	}
	conn, err := sctp.DialSCTPExt("sctp", nil, addr, init)
	if err != nil {
		return nil, fmt.Errorf("DialSCTPExt failed: %w", err)
	}
	return conn, nil
}

func (sc *SctpConn) ListenAMF(conn *sctp.SCTPConn, msgRevChan chan<- []byte) {
	for {
		recvBuf := make([]byte, 4096)
		n, err := conn.Read(recvBuf)
		if err != nil {
			log.Fatalf("Failed to read NGAP: %v", err)
			return
		}

		fmt.Printf("Received from AMF: raw bytes (%d bytes): % X\n", n, recvBuf[:n])

		msgRevChan <- recvBuf[:n]
	}
}

func (sc *SctpConn) Send(msg []byte) (err error) {
	// SCTP write
	info := &sctp.SndRcvInfo{Stream: 0, PPID: 60}
	_, err = sc.conn.SCTPWrite(msg, info)
	if err != nil {
		return err
	}
	return nil
}

func (sc *SctpConn) GetConn() *sctp.SCTPConn {
	return sc.conn
}
