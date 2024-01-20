package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/Ullaakut/nmap/v3"
	"github.com/brian-l-johnson/nmap-agent-go/v2/models"
)

func main() {
	/*
		jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
		if err != nil {
			panic(err)
		}
		client := &http.Client{
			Jar: jar,
		}

		resp, err := client.Get("http://127.0.0.1:8080/auth/status")
		if err != nil {
			panic(err)
		}
		fmt.Println("---resp---")
		fmt.Println(resp.Body.Read())
	*/

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	// Equivalent to `/usr/local/bin/nmap -p 80,443,843 google.com facebook.com youtube.com`,
	// with a 5-minute timeout.
	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets("192.168.1.1/24"),
		nmap.WithPorts("80,443,843"),
		nmap.WithVersionAll(),
		nmap.WithOSDetection(),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	result, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		log.Printf("run finished with warnings: %s\n", *warnings) // Warnings are non-critical errors from nmap.
	}
	if err != nil {
		log.Fatalf("unable to run nmap scan: %v", err)
	}

	var hosts []models.Host

	// Use the results to print an example output
	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		fmt.Printf("Host %q:\n", host.Addresses[0])

		var ports []models.Port

		for _, port := range host.Ports {
			fmt.Printf("\tPort %d/%s %s %s\n", port.ID, port.Protocol, port.State, port.Service.Name)
			if port.Status() == nmap.Open {
				ports = append(ports, models.Port{Id: port.ID, Protocol: port.Protocol, State: port.State.String(), Service: port.Service.Name})
			}
		}
		os := ""
		if len(host.OS.Matches) > 0 {
			os = host.OS.Matches[0].Name
		}
		hostname := ""
		if len(host.Hostnames) > 0 {
			hostname = host.Hostnames[0].String()
		}

		hosts = append(hosts, models.Host{IP: host.Addresses[0].String(), Ports: ports, OS: os, Hostname: hostname})
	}

	fmt.Printf("Nmap done: %d hosts up scanned in %.2f seconds\n", len(result.Hosts), result.Stats.Finished.Elapsed)

	scan := models.Scan{Status: result.Stats.Finished.Summary, StartTime: time.Time(result.Start), EndTime: time.Time(result.Stats.Finished.Time), Hosts: hosts}
	//fmt.Println(scan)
	//scanJson, _ := json.Marshal(result)
	scanJson, _ := json.Marshal(scan)
	fmt.Println(string(scanJson))

}
