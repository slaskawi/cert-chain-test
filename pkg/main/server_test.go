package main

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net/http"
	"os/exec"
	"testing"
)

func TestCerts(t *testing.T) {
	createCerts()

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
			// The Server uses intermediary and the Client uses CA only.
			// Note how we configure OpenSSL:
			// basicConstraints = critical, CA:true, pathlen:0
			// keyUsage = critical, digitalSignature, cRLSign, keyCertSign
			// The CA flag needs to be false, and we need to use proper key Usages.
			// The assumption is that an intermediary key might be used for further signing...
			name: "Server[Intermediary] Client[CA] => should connect",
			args: args{
				ServerKey:         "certs/generated/Intermediary.key",
				ServerCert:        "certs/generated/Intermediary.crt",
				ClientTrustBundle: "certs/generated/Trustbundle_CA.crt",
				shouldConnect:     true,
			},
		},
		{
			// This should pass as we have the CA Trustbundle at hand
			name: "Server[Leaf signed by CA] Client[CA] => should connect",
			args: args{
				ServerKey:         "certs/generated/Leaf_signed_by_CA.key",
				ServerCert:        "certs/generated/Leaf_signed_by_CA.crt",
				ClientTrustBundle: "certs/generated/Trustbundle_CA.crt",
				shouldConnect:     true,
			},
		},
		{
			// This should pass as the intermediate is also signed by CA.
			name: "Server[Leaf signed by Intermediate] Client[CA] => should connect",
			args: args{
				ServerKey:         "certs/generated/Leaf_signed_by_Intermediary.key",
				ServerCert:        "certs/generated/Leaf_signed_by_Intermediary.crt",
				ClientTrustBundle: "certs/generated/Trustbundle_CA.crt",
				shouldConnect:     true,
			},
		},
		{
			// !!!!
			// This is the first interesting case.
			// The Client doesn't have the full certificate chain but only the intermediate match.
			// In theory, this should be a match but unfortunately it fails...
			// !!!!
			name: "Server[Leaf signed by Intermediate] Client[Intermediary Rootless] => should connect but doesn't",
			args: args{
				ServerKey:         "certs/generated/Leaf_signed_by_Intermediary.key",
				ServerCert:        "certs/generated/Leaf_signed_by_Intermediary.crt",
				ClientTrustBundle: "certs/generated/Trustbundle_Intermediary_Full_Chain_Rootless.crt",
				shouldConnect:     false,
			},
		},
		{
			// !!!!
			// This is the second interesting case.
			// Similarly to the previous case, but now the Client has the full certificate chain along with the Root
			// It's a match!
			// !!!!
			name: "Server[Leaf signed by Intermediate] Client[Intermediary Rootless] => should connect but doesn't",
			args: args{
				ServerKey:         "certs/generated/Leaf_signed_by_Intermediary.key",
				ServerCert:        "certs/generated/Leaf_signed_by_Intermediary.crt",
				ClientTrustBundle: "certs/generated/Trustbundle_Intermediary_Full_Chain.crt",
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
			//fmt.Printf("Just informative - err: %v\n", err)
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

func createCerts() {
	cmd := exec.Command("./certs/create_certs.sh")

	err := cmd.Run()

	if err != nil {
		panic(err)
	}

	out, _ := cmd.Output()
	println(string(out))
}
