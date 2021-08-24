package main

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
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
			// This is a bit counterintuitive. The Leaf certificate is signed by the Intermediary, which
			// is signed by CA. The Client has only CA in his hands, therefore it doesn't know anything about
			// the intermediary. The only way to verify this scenario is to put both Intermediary.crt and CA.crt
			// into the Trust Bundle (see the testcase below).
			// Bonus point: You can verify this using openssl:
			//   openssl verify -CAfile ./generated/Trustbundle_CA.crt ./generated/Leaf_signed_by_Intermediary.crt
			//   CN = delta
			//   error 20 at 0 depth lookup: unable to get local issuer certificate
			//   error ./generated/Leaf_signed_by_Intermediary.crt: verification failed
			name: "Server[Leaf signed by Intermediate] Client[CA] => shouldn't connect",
			args: args{
				ServerKey:         "certs/generated/Leaf_signed_by_Intermediary.key",
				ServerCert:        "certs/generated/Leaf_signed_by_Intermediary.crt",
				ClientTrustBundle: "certs/generated/Trustbundle_CA.crt",
				shouldConnect:     false,
			},
		},
		{
			// Have a look at the description of the above test case.
			name: "Server[Leaf signed by Intermediate] Client[CA + Intermediary] => shouldn't connect",
			args: args{
				ServerKey:         "certs/generated/Leaf_signed_by_Intermediary.key",
				ServerCert:        "certs/generated/Leaf_signed_by_Intermediary.crt",
				ClientTrustBundle: "certs/generated/Trustbundle_Intermediary_Full_Chain.crt",
				shouldConnect:     true,
			},
		},
		{
			// This is the most interesting case. We use the Intermediary cert without the root. Since the
			// intermediary is CA, this should be fine.
			name: "Server[Leaf signed by Intermediate] Client[Intermediary Rootless] => should connect",
			args: args{
				ServerKey:         "certs/generated/Leaf_signed_by_Intermediary.key",
				ServerCert:        "certs/generated/Leaf_signed_by_Intermediary.crt",
				ClientTrustBundle: "certs/generated/Trustbundle_Intermediary_Full_Chain_Rootless.crt",
				shouldConnect:     true,
			},
		},
		{
			// A similar test to the one the above but with full certificate chain.
			name: "Server[Leaf signed by Intermediate] Client[Intermediary Rootless] => should connect",
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

			// Read in the cert file
			certs, err := ioutil.ReadFile(tt.args.ClientTrustBundle)
			if err != nil {
				panic(err)
			}

			trustedCertPool := x509.NewCertPool()
			if ok := trustedCertPool.AppendCertsFromPEM(certs); !ok {
				panic("Failed to append certs from file")
			}
			
			config := &tls.Config{
				RootCAs: trustedCertPool,
			}

			tr := &http.Transport{TLSClientConfig: config}
			client := &http.Client{Transport: tr}
			resp, err := client.Get(GetServerAddress())
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
	cmd := exec.Command("./create_certs.sh")
	cmd.Dir = "./certs"
	err := cmd.Run()

	if err != nil {
		panic(err)
	}

	out, _ := cmd.Output()
	println(string(out))
}
