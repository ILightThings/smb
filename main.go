package main

import (
	"log"

	"github.com/ilightthings/smb/smb"
)

func main() {

	host := "172.16.248.192"
	options := smb.Options{
		Host:        host,
		Port:        445,
		User:        "alice",
		Domain:      "corp",
		Workstation: "",
		Password:    "Password123!",
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

	if session.IsAuthenticated {
		log.Println("[+] Login successful")
	} else {
		log.Println("[-] Login failed")
	}

	if err != nil {
		log.Fatalln("[!]", err)
	}
}
