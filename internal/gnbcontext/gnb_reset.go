package gnbcontext

import "fmt"

func (gnb *GnbContext) ResetUeState() {
	fmt.Println("[gNB] Resetting UE state for new registration")
	
	gnb.RanUeNgapId++  // Increment for new UE
	gnb.AmfUeNgapId = 0
	gnb.initialSent = false
	gnb.ueContextReady = false
	
	// Clear NAS buffer
	for len(gnb.nasBuf) > 0 {
		<-gnb.nasBuf
	}
	
	fmt.Printf("[gNB] New RAN UE NGAP ID: %d\n", gnb.RanUeNgapId)
}