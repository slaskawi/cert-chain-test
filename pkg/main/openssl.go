package main

import (
	"os"
	"os/exec"
)

func IsValidWithOpenSSL(serverCert, ca string) bool {
	cmd := exec.Command("openssl", "verify", "-CAfile", ca, serverCert)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			return false
		}
	}

	return true;
}
