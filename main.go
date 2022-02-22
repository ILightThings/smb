package main

import (
	"fmt"
	"log"

	"github.com/ilightthings/smb/smb"
	"github.com/ilightthings/smb/smb/enum"
)

func main() {

	host := "172.16.0.10"
	options := smb.Options{
		Host:        host,
		Port:        445,
		User:        "administrator",
		Domain:      "light",
		Workstation: "",
		Password:    "123Admin123!!",
	}
	debug := false
	session, err := smb.NewSession(options, debug)
	if err != nil {
		log.Fatalln("[!]", err)
	}
	defer session.Close()

	if session.IsSigningRequired {
		log.Println("[-] Signing is required")
	} else {
		log.Println("[+] Signing is NOT required")
	}

	if err != nil {
		log.Fatalln("[!]", err)
	}

	workstation := enum.BuildWorkstation(session)
	fmt.Println(len(workstation.Reserve))
}
