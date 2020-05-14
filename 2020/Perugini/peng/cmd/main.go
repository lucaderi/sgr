package main

import (
	"flag"
	"fmt"
	p "github.com/alessio-perugini/peng"
	"github.com/google/gopacket/pcap"
	"log"
	"net/url"
	"os"
	"time"
)

var (
	config = p.Config{
		NumberOfBin:        128,
		SizeBitmap:         1024,
		InfluxUrl:          "http://localhost",
		InfluxPort:         9999,
		InfluxBucket:       "",
		InfluxOrganization: "",
		InfluxAuthToken:    "",
		SaveFilePath:       "",
		UseInflux:          false,
		Verbose:            uint(0),
		NetworkInterface:   "",
	}
	timeFrame = "1m"

	showInterfaceNames bool
	versionFlag        bool
	version            = "0.0.0"
	commit             = "commithash"
)

func init() {
	//Bitmap
	flag.UintVar(&config.NumberOfBin, "bin", 16, "number of bin in your bitmap")
	flag.UintVar(&config.SizeBitmap, "size", 1024, "size of your bitmap")

	//influx
	flag.StringVar(&config.InfluxUrl, "influxUrl", "http://localhost", "influx url")
	flag.UintVar(&config.InfluxPort, "influxPort", 9999, "influxPort number")
	flag.StringVar(&config.InfluxBucket, "bucket", "", "bucket string for telegraf")
	flag.StringVar(&config.InfluxOrganization, "org", "", "organization string for telegraf")
	flag.StringVar(&config.InfluxAuthToken, "token", "", "auth token for influxdb")

	//other
	flag.BoolVar(&versionFlag, "version", false, "output version")
	flag.StringVar(&config.SaveFilePath, "export", "", "file path to save the peng result as csv")
	flag.StringVar(&timeFrame, "timeFrame", "1m", "interval time to detect scans. Number + (s = seconds, m = minutes, h = hours)")
	flag.UintVar(&config.Verbose, "verbose", 1, "set verbose level (1-3)")
	flag.StringVar(&config.NetworkInterface, "network", "", "name of your network interface")
	flag.BoolVar(&showInterfaceNames, "interfaces", false, "show the list of all your network interfaces")
}

func flagConfig() {
	appString := fmt.Sprintf("________                     \n___  __ \\__________________ _\n__  /_/ /  _ \\_  __ \\_  __ `/\n_  ____//  __/  / / /  /_/ / \n/_/     \\___//_/ /_/_\\__, /  \n                    /____/   \n"+
		"version %s %s", version, commit)

	flag.Usage = func() { //help flag
		fmt.Fprintf(flag.CommandLine.Output(), "%s\n\nUsage: sys-status [options]\n", appString)
		flag.PrintDefaults()
	}

	flag.Parse()

	if versionFlag { //version flag
		fmt.Fprintf(flag.CommandLine.Output(), "%s\n", appString)
		os.Exit(2)
	}

	if showInterfaceNames {
		interfaces, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatal(err.Error())
		}
		for _, v := range interfaces {
			fmt.Printf("name: \"%s\"\n\t %s %s %d \n", v.Name, v.Description, v.Addresses, v.Flags)
		}
		os.Exit(2)
	}

	if config.NetworkInterface == "" {
		log.Fatal("You must provide the device adapter you want to listen to")
	}

	if config.InfluxAuthToken != "" && config.InfluxBucket == "" && config.InfluxOrganization == "" {
		log.Fatal("You must provide bucket, organization and influxAuthToken")
	}

	if _, err := url.ParseRequestURI(config.InfluxUrl); err != nil {
		log.Fatal("Influx url is not valid")
	}

	if config.InfluxAuthToken == "" && config.SaveFilePath == "" && config.Verbose == 0 {
		log.Fatal("You must provide at least 1 method to send or display the data")
	}

	//Check timeFrame input to perform port scan detection
	if v, err := time.ParseDuration(timeFrame); err != nil {
		log.Fatal("Invalid interval format.")
	} else if v.Seconds() <= 0 {
		log.Fatal("Interval too short it must be at least 1 second long")
	} else {
		config.TimeFrame = v
	}

	//check if user exceed maximum allowed verbosity
	if config.Verbose > 3 {
		config.Verbose = 3
	}

	if config.SizeBitmap > 1<<16 {
		log.Fatal("Size of full bitmap is too big, it must be less than 65536")
	}

	fmt.Printf("%s\n", appString)
}

func main() {
	flagConfig()

	peng := p.New(&config)
	peng.Start()

}
