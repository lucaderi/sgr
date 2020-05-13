package portbitmap

import (
	"errors"
	b "github.com/alessio-perugini/peng/pkg/bitmap"
	"math"
)

type PortBitmap struct {
	Config      *Config
	InnerBitmap []b.Bitmap
	HashFunc    func(port uint16) (uint16, uint64)
}

type Config struct {
	NumberOfBin  uint
	SizeBitmap   uint
	NumberOfBits uint
}

var epsilon = math.Nextafter(1.0, 2.0) - 1.0

func New(cfg *Config) *PortBitmap {
	var InnerBitmap = make([]b.Bitmap, cfg.NumberOfBin)
	cfg.NumberOfBits = cfg.SizeBitmap / cfg.NumberOfBin

	for i := 0; i < int(cfg.NumberOfBin); i++ {
		InnerBitmap[i] = *b.New(uint64(cfg.NumberOfBits))
	}

	var hashFunc = func(port uint16) (uint16, uint64) {
		portModuled := (port / uint16(cfg.NumberOfBin)) % uint16(cfg.SizeBitmap)
		index, bit := portModuled/uint16(cfg.NumberOfBits), uint64(portModuled)%uint64(cfg.NumberOfBits)
		return index, bit
	}

	return &PortBitmap{
		InnerBitmap: InnerBitmap,
		HashFunc:    hashFunc,
		Config:      cfg,
	}
}

func (p *PortBitmap) AddPort(port uint16) error {
	indexBin, bitBin := p.HashFunc(port)
	if indexBin >= uint16(len(p.InnerBitmap)) {
		return errors.New("index to access the bin is invalid")
	}
	if insert := p.InnerBitmap[indexBin].SetBit(bitBin, true); !insert {
		return errors.New("bit offset too big")
	}
	return nil
}

func (p *PortBitmap) ClearAll() {
	for i := 0; i < len(p.InnerBitmap); i++ {
		p.InnerBitmap[i].ResetAllBits()
	}
}

//https://rosettacode.org/wiki/Entropy
func (p *PortBitmap) EntropyOfEachBin() []float64 {
	var total = float64(p.Config.NumberOfBits)             //number of bits in the bin
	var sum float64                                        //used to compute the entropy
	allEntropy := make([]float64, 0, p.Config.NumberOfBin) //used to calculate entropy of each bin

	for i := 0; i < len(p.InnerBitmap); i++ {
		bitsAt1 := float64(p.InnerBitmap[i].GetBitSets()) / total
		bitsAt0 := float64(uint64(p.Config.NumberOfBits)-p.InnerBitmap[i].GetBitSets()) / total

		if bitsAt1 > epsilon && bitsAt0 > epsilon {
			sum -= bitsAt1 * math.Log(bitsAt1)
			sum -= bitsAt0 * math.Log(bitsAt0)
		}
		sum = sum / math.Log(2.0)
		//this helps me to identifies the number of scanned port in entropy form
		if bitsAt1 > bitsAt0 { //so i can distinguish if i'm in the range of [0-1] or [1-0] in term of standard gaussian
			sum = 2 - sum //used to allow growth of entropy in wider range [0-2]
		}

		allEntropy = append(allEntropy, sum)
		sum = 0
	}

	return allEntropy
}

func (p *PortBitmap) EntropyTotal() float64 {
	binsEntropy := p.EntropyOfEachBin()
	var totalEntropy float64

	for _, v := range binsEntropy {
		totalEntropy += v
	}

	return totalEntropy / float64(p.Config.NumberOfBin)
}
