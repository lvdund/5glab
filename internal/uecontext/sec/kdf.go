package sec

import "github.com/reogac/nas"

// Wrapper to provide UL/DL counter functions
type NasContextWrapper struct {
	nc      *nas.NasContext
	UlCount uint32
	DlCount uint32
}

func NewNasContextWrapper(nc *nas.NasContext) *NasContextWrapper {
	return &NasContextWrapper{nc: nc}
}

func (ctx *NasContextWrapper) UlCounter() uint32 {
	return ctx.UlCount
}

func (ctx *NasContextWrapper) DlCounter() uint32 {
	return ctx.DlCount
}

func (ctx *NasContextWrapper) IncrementUlCount() {
	ctx.UlCount++
}

func (ctx *NasContextWrapper) IncrementDlCount() {
	ctx.DlCount++
}

func (ctx *NasContextWrapper) SelectedAlgorithms() (encAlg, intAlg uint8) {
	return ctx.nc.SelectedAlgorithms()
}
