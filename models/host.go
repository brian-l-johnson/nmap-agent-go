package models

type Host struct {
	IP       string
	Hostname string
	OS       string
	Ports    []Port
}
