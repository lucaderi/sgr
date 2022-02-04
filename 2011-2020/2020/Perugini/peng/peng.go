package peng

import (
	"fmt"
	"github.com/alessio-perugini/peng/pkg/portbitmap"
	"github.com/google/gopacket"
	_ "github.com/google/gopacket/layers" //Used to init internal struct
	"github.com/google/gopacket/pcap"
	"log"
	"os"
	"os/signal"
	"time"
)

type Peng struct {
	Config                       *Config
	ClientTraffic, ServerTraffic *portbitmap.PortBitmap
}

type Config struct {
	NumberOfBin        uint
	SizeBitmap         uint
	NumberOfBits       uint
	SaveFilePath       string
	NetworkInterface   string
	UseInflux          bool
	InfluxUrl          string
	InfluxPort         uint
	InfluxBucket       string
	InfluxOrganization string
	InfluxAuthToken    string
	Verbose            uint
	TimeFrame          time.Duration
}

func New(cfg *Config) *Peng {
	cfg.NumberOfBits = cfg.SizeBitmap / cfg.NumberOfBin
	bitmapConfig := &portbitmap.Config{
		NumberOfBin:  cfg.NumberOfBin,
		SizeBitmap:   cfg.SizeBitmap,
		NumberOfBits: cfg.NumberOfBits,
	}
	var peng = Peng{
		Config:        cfg,
		ClientTraffic: portbitmap.New(bitmapConfig),
		ServerTraffic: portbitmap.New(bitmapConfig),
	}

	return &peng
}

func (p *Peng) Start() {
	getMyIp()

	pHandle, err := pcap.OpenLive(
		p.Config.NetworkInterface,
		int32(65535),
		false,
		pcap.BlockForever)

	if err != nil {
		log.Fatal(err)
	}
	defer pHandle.Close()

	go func() {
		packet := gopacket.NewPacketSource(pHandle, pHandle.LinkType())

		time.AfterFunc(p.Config.TimeFrame, p.handler)
		for packet := range packet.Packets() {
			p.inspect(packet)
		}
	}()
	sig := make(chan os.Signal, 1024)
	signal.Notify(sig, os.Interrupt)
	<-sig
	log.Println("Quitting Peng, bye!")
}

func (p *Peng) PrintAllInfo() {
	allPortTraffic := []*portbitmap.PortBitmap{p.ClientTraffic, p.ServerTraffic}
	for i, v := range allPortTraffic {
		if p.Config.Verbose == 3 {
			fmt.Println(v) //Print all bitmap
			fmt.Println("Bit set: ")
			for i := 0; i < len(v.InnerBitmap); i++ {
				fmt.Println("bin number [", i, "]    num (bit at 1): ", v.InnerBitmap[i].GetBitSets())
			}
		}
		if p.Config.Verbose >= 1 {
			if i == 0 {
				fmt.Printf("[%s] [CLIENT] ", time.Now().Local().String())
			} else {
				fmt.Printf("[%s] [SERVER] ", time.Now().Local().String())
			}
		}
		if p.Config.Verbose >= 2 {
			fmt.Printf("entropy of each bin: %f\n", v.EntropyOfEachBin())
		}
		if p.Config.Verbose >= 1 {
			fmt.Printf("total entropy: %f\n", v.EntropyTotal())
		}
	}
}

func (p *Peng) handler() {
	p.PushToInfluxDb()
	p.ExportToCsv()

	p.PrintAllInfo()

	//Clear bitmap for the new reader
	p.ClientTraffic.ClearAll()
	p.ServerTraffic.ClearAll()

	//Wait timeframe time, before further actions
	time.AfterFunc(p.Config.TimeFrame, p.handler)
}
