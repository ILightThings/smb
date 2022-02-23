package main

import (
	"fmt"
	"log"

	"github.com/ilightthings/smb/smb"
	"github.com/ilightthings/smb/smb/enum"
)

// TODO Make this somehow cleaner
func main() {

	host := "192.168.1.161"
	options := smb.Options{
		Host: host,
		Port: 445,
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

	workstation := enum.EnumerateWorkstation(session)
	fmt.Println(len(workstation.Reserve))
}
