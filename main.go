package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"os"
	"time"

	"github.com/Ullaakut/nmap/v3"
	"github.com/brian-l-johnson/nmap-agent-go/v2/models"
	"github.com/joho/godotenv"
	"golang.org/x/net/publicsuffix"
)

func doLogin(client *http.Client) {
	loginVals := map[string]string{"user": os.Getenv("API_USER"), "password": os.Getenv("API_PASS")}
	jsonValue, _ := json.Marshal(loginVals)
	resp, err := client.Post(os.Getenv("API_URL_BASE")+"/auth/login", "application/json", bytes.NewBuffer(jsonValue))
	if err != nil {
		panic("unable to login")
	}
	resBody, _ := io.ReadAll(resp.Body)
	fmt.Printf("login resp: %s\n", resBody)

}

func getJob(client *http.Client) models.Job {
	resp, err := client.Get(os.Getenv("API_URL_BASE") + "/jobs/nmap/next")
	if err != nil {
		panic("unable to get job")
	}
	var job models.Job
	json.NewDecoder(resp.Body).Decode(&job)
	fmt.Printf("got job: type: %s, range: %s\n", job.Type, job.IPRange)

	return job
}

func postResult(client *http.Client, scanJson string, job models.Job) {
	url := fmt.Sprintf(os.Getenv("API_URL_BASE")+"/jobs/nmap/%s", job.JID)

	resp, err := client.Post(url, "application/json", bytes.NewBuffer([]byte(scanJson)))
	if err != nil {
		panic("failed to post results")
	}
	resBody, _ := io.ReadAll(resp.Body)
	fmt.Printf("scan upload resp: %s", resBody)

}

func main() {

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		panic(err)
	}
	client := &http.Client{
		Jar: jar,
	}

	doLogin(client)
	job := getJob(client)

	/*

		resp, err := client.Get("http://127.0.0.1:8080/auth/status")
		if err != nil {
			panic(err)
		}
		fmt.Println("---resp---")
		resBody, err := io.ReadAll(resp.Body)

		fmt.Printf("response: %s\n", resBody)

	*/

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	// Equivalent to `/usr/local/bin/nmap -p 80,443,843 google.com facebook.com youtube.com`,
	// with a 5-minute timeout.
	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(job.IPRange),
		nmap.WithVersionAll(),
		nmap.WithOSDetection(),
		nmap.WithSYNScan(),
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
				ports = append(ports, models.Port{Number: port.ID, Protocol: port.Protocol, State: port.State.String(), Service: port.Service.Name})
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
	postResult(client, string(scanJson), job)

}
