package logger

import (
	"encoding/hex"
	"log"
)

func LogHexDump(prefix string, pdu []byte) {
	log.Printf("%s (length: %d bytes):\n%s", prefix, len(pdu), hex.Dump(pdu))
}

func LogMessageContent(prefix string, msg interface{}) {
	log.Printf("%s: %v", prefix, msg)
}
