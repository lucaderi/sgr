package main

import (
	"flag"
	"fmt"
	"github.com/influxdata/influxdb-client-go"
	g "github.com/soniah/gosnmp"
	"log"
	"math/big"
	"net/url"
	"os"
	"os/signal"
	"os/user"
	"time"
)

var oids = map[string]string{
	//IF-MIB
	"ifHCInOctets":  ".1.3.6.1.2.1.31.1.1.1.6.2",
	"ifHCOutOctets": ".1.3.6.1.2.1.31.1.1.1.10.2",
}

type systemInfo struct {
	network netInfo
}

type netInfo struct {
	ifHCInOctets  big.Int
	ifHCoutOctets big.Int
	lastUpdate    int64
}

var (
	hostnameSnmp string
	community    string
	snmpPort     uint

	influxUrl       string
	bucket          string
	organization    string
	influxPort      uint
	versionFlag     bool
	interval        string
	influxAuthToken string

	version = "0.0.0"
	commit  = "commithash"
	sysInfo = systemInfo{}
)

func init() {
	flag.StringVar(&hostnameSnmp, "host", "localhost", "hostnameSnmp or ip address")
	flag.StringVar(&community, "community", "public", "community string for snmp")
	flag.UintVar(&snmpPort, "snmpPort", 161, "snmp port number")

	flag.StringVar(&influxUrl, "influxUrl", "http://localhost", "influx url")
	flag.UintVar(&influxPort, "influxPort", 9999, "influxPort number")
	flag.StringVar(&bucket, "bucket", "", "bucket string for telegraf")
	flag.StringVar(&organization, "org", "", "organization string for telegraf")
	flag.StringVar(&influxAuthToken, "token", "", "auth token for influxdb")

	flag.StringVar(&interval, "interval", "2s", "interval in seconds before send another snmp request")
	flag.BoolVar(&versionFlag, "version", false, "output version")
}

func main() {
	flagConfig()
	maxTime, _ := time.ParseDuration(interval)

	//snmp config
	g.Default.Target = hostnameSnmp
	g.Default.Community = community
	g.Default.Port = uint16(snmpPort)

	err := g.Default.Connect() //Open snmp connection
	if err != nil {
		log.Fatalf("Connect() err: %v", err)
	}

	defer func() { //Close snmp connection
		if err := g.Default.Conn.Close(); err != nil {
			log.Println(err)
		}
	}()

	client := influxdb2.NewClient(influxUrl+":"+fmt.Sprint(influxPort), influxAuthToken)
	defer client.Close()
	writeApi := client.WriteApi(organization, bucket) //non-blocking

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for sig := range c {
			fmt.Println(sig)
			writeApi.Flush() // Force all unwritten data to be sent
			os.Exit(1)
		}
	}()

	//Get os user
	username, err := user.Current()
	if err != nil {
		panic(err)
	}

	for {
		tStart := time.Now()

		getNetwork()
		if isMaxTimeExpired(tStart, maxTime) {
			continue
		}

		//Send point of system with hostname and values about in and out bits
		p := influxdb2.NewPoint(
			"system",
			map[string]string{
				"hostname": username.Username,
			},
			map[string]interface{}{
				"in":  sysInfo.network.ifHCInOctets.Int64(),
				"out": sysInfo.network.ifHCoutOctets.Int64(),
			},
			time.Now())

		writeApi.WritePoint(p)

		timeToSleep := maxTime - time.Since(tStart)
		time.Sleep(timeToSleep)
	}
}

func isMaxTimeExpired(start time.Time, maxDuration time.Duration) bool {
	elapsedTime := time.Since(start)
	return elapsedTime > maxDuration
}

//Flag config
func flagConfig() {
	appString := fmt.Sprintf("sys-status version %s %s", version, commit)

	flag.Usage = func() { //help flag
		fmt.Fprintf(flag.CommandLine.Output(), "%s\n\nUsage: sys-status [options]\n", appString)
		flag.PrintDefaults()
	}

	flag.Parse()

	if versionFlag { //version flag
		fmt.Fprintf(flag.CommandLine.Output(), "%s\n", appString)
		os.Exit(2)
	}

	if bucket == "" || organization == "" || influxAuthToken == "" {
		log.Fatal("You must provide bucket, organization and influxAuthToken")
	}

	if _, err := url.ParseRequestURI(influxUrl); err != nil {
		log.Fatal("Influx url is not valid")
	}

	//Check interval input used to gather data with snmp
	if v, err := time.ParseDuration(interval); err != nil {
		log.Fatal("Invalid interval format.")
	} else if v.Seconds() <= 0 {
		log.Fatal("Interval too short it must be at least 1 second long")
	}

	fmt.Printf("%s\n", appString)
}

//Parse variable of snmp lib to bigint
func parserVariable(v g.SnmpPDU) big.Int {
	return *g.ToBigInt(v.Value)
}

func getNetwork() {
	netInfoArr := []string{oids["ifHCInOctets"], oids["ifHCOutOctets"]}
	result, err := g.Default.Get(netInfoArr) // Send snmp get and retrieve values up to g.MAX_OIDS

	if err != nil {
		log.Fatalf("Get() err: %v", err)
	}

	newIn := parserVariable(result.Variables[0])
	newOut := parserVariable(result.Variables[1])

	sysInfo = systemInfo{
		network: netInfo{
			ifHCInOctets:  newIn,
			ifHCoutOctets: newOut,
			lastUpdate:    time.Now().UnixNano(),
		},
	}

}
