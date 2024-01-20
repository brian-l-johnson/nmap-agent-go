package models

type Port struct {
	Id       uint16
	State    string
	Protocol string
	Service  string
}
