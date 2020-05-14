package peng

import (
	"encoding/csv"
	"fmt"
	influxdb2 "github.com/influxdata/influxdb-client-go"
	"log"
	"os"
	"time"
)

func (p *Peng) PushToInfluxDb() {
	if p.Config.InfluxAuthToken == "" {
		return
	}

	//Get entropy and set data to influx
	client := influxdb2.NewClient(p.Config.InfluxUrl+":"+fmt.Sprint(p.Config.InfluxPort), p.Config.InfluxAuthToken)
	defer client.Close()
	writeApi := client.WriteApi(p.Config.InfluxOrganization, p.Config.InfluxBucket) //non-blocking

	//Send point of system with hostname and values about in and out bits
	point := influxdb2.NewPoint(
		"system",
		map[string]string{
			"entropy": "ports",
		},
		map[string]interface{}{
			"in":  p.ServerTraffic.EntropyTotal(),
			"out": p.ClientTraffic.EntropyTotal(),
		},
		time.Now())
	writeApi.WritePoint(point)
	writeApi.Flush() // Force all unwritten data to be sent

	if p.Config.Verbose == 3 {
		fmt.Printf("[%s] file successfully pushed to influxdb\n", time.Now().Local().String())
	}
}

func (p *Peng) ExportToCsv() {
	if p.Config.SaveFilePath == "" {
		return
	}

	// 1. Open the file
	file, err := os.OpenFile(p.Config.SaveFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0777)
	if err != nil {
		log.Println("error opening csv file", err.Error())
	}

	defer file.Close()

	currTime := time.Now().Local().String()
	writer := csv.NewWriter(file)
	var csvData = [][]string{
		{currTime, fmt.Sprintf("%f", p.ClientTraffic.EntropyTotal()), fmt.Sprintf("%f", p.ServerTraffic.EntropyTotal())},
	}
	// 3. Write all the records
	err = writer.WriteAll(csvData) // returns error
	if err != nil {
		log.Println("error on writing csv data ", err.Error())
		return
	}
	err = file.Chown(65534, 65534)
	if err != nil {
		fmt.Println(err.Error())
	}

	if p.Config.Verbose == 3 {
		fmt.Printf("[%s] data successfully exported to csv\n", time.Now().Local().String())
	}
}
