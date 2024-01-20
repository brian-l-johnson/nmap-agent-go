package models

import "time"

type Scan struct {
	Status    string
	StartTime time.Time
	EndTime   time.Time
	Hosts     []Host
}
