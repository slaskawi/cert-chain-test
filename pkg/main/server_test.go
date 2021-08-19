package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"testing"
)

func TestCerts(t *testing.T) {
	type args struct {
		ServerKey         string
		ServerCert        string
		ClientTrustBundle string
		shouldConnect     bool
	}
	tests := []struct {
		name string
		args args
	}{
		{
			// Server and Client match perfectly - no surprise they can connect.
			name: "Server[CA] Client[CA] => should connect",
			args: args{
				ServerKey:         "certs/generated/CA.key",
				ServerCert:        "certs/generated/CA.crt",
				ClientTrustBundle: "certs/generated/Trustbundle_CA.crt",
				shouldConnect:     true,
			},
		},
		{
			// The Client has a full chain with the Root. So again - perfect match.
			name: "Server[Intermediary] Client[Intermediary + CA] => should connect",
			args: args{
				ServerKey:         "certs/generated/Intermediary.key",
				ServerCert:        "certs/generated/Intermediary.crt",
				ClientTrustBundle: "certs/generated/Trustbundle_Intermediary_Full_Chain.crt",
				shouldConnect:     true,
			},
		},
		{
			// The Client has a matching Cert but don't have CA. This passes in Go.
			name: "Server[Intermediary] Client[Intermediary Rootless] => should connect",
			args: args{
				ServerKey:         "certs/generated/Intermediary.key",
				ServerCert:        "certs/generated/Intermediary.crt",
				ClientTrustBundle: "certs/generated/Trustbundle_Intermediary_Full_Chain_Rootless.crt",
				shouldConnect:     true,
			},
		},
		{
			// This one is strange to me.
			// The Server uses cert signed by CA.
			// The Client uses a trust bundle with CA only.
			// It fails with:
			// Get "https://local.localhost:8443": x509: certificate signed by unknown authority (possibly because of "x509: invalid signature: parent certificate cannot sign this kind of certificate" while trying to verify candidate authority certificate "*.localhost")
			name: "Server[Intermediary] Client[CA] => should connect",
			args: args{
				ServerKey:         "certs/generated/Intermediary.key",
				ServerCert:        "certs/generated/Intermediary.crt",
				ClientTrustBundle: "certs/generated/Trustbundle_CA.crt",
				shouldConnect:     true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			StartSever(tt.args.ServerKey, tt.args.ServerCert)

			// Stolen from https://forfuncsake.github.io/post/2017/08/trust-extra-ca-cert-in-go-app/
			rootCAs, _ := x509.SystemCertPool()
			if rootCAs == nil {
				rootCAs = x509.NewCertPool()
			}

			// Read in the cert file
			certs, err := ioutil.ReadFile(tt.args.ClientTrustBundle)
			if err != nil {
				panic(err)
			}

			// Append our cert to the system pool
			if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
				log.Println("No certs appended, using system certs only")
			}

			// Trust the augmented cert pool in our client
			config := &tls.Config{
				RootCAs:            rootCAs,
			}
			tr := &http.Transport{TLSClientConfig: config}
			client := &http.Client{Transport: tr}

			req, err := http.NewRequest(http.MethodGet, "https://local.localhost:8443", nil)
			if err != nil {
				panic(err)
			}
			resp, err := client.Do(req)
			hasConnected := err == nil
			fmt.Printf("Just informative - err: %v\n", err)
			if tt.args.shouldConnect != hasConnected {
				t.Fatalf("Expected shouldConnect=%v but found err=%v", tt.args.shouldConnect, err)
			}
			if err == nil {
				resp.Body.Close()
			}
			StopServer()

		})
	}
}
