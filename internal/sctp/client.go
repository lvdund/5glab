package sctp

import (
	"fmt"
	"net"
	"github.com/ishidawataru/sctp"
)

func ConnectToAmf( amfIP string, amfPort int) (*sctp.SCTPConn, error){
	addr := &sctp.SCTPAddr{
		IPAddrs : []net.IPAddr{
			{IP : net.ParseIP(amfIP)},	
		},
		Port : amfPort,
	}
	init := sctp.InitMsg{
		NumOstreams    : 10,
		MaxInstreams   : 10,
		MaxAttempts    :4,
		MaxInitTimeout :60,
		}
	conn, err := sctp.DialSCTPExt("sctp", nil, addr, init)
	if err != nil {
		return nil, fmt.Errorf("DialSCTPExt failed: %w",err)
	}
	return conn, nil
}








































