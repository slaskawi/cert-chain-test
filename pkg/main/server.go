package main

//Awfully written - don't look, or you go blind...

import (
	"crypto/tls"
	"net"
	"net/http"
)

var srv http.Server
var listener net.Listener

func StartSever(key, cert string) {
	servingTLSCertificate, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		panic(err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{servingTLSCertificate},
	}
	srv = http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
		TLSConfig: cfg,
	}

	listener, err = net.Listen("tcp", ":0")
	if err != nil {
		panic(err)
	}

	go func() {
		srv.ServeTLS(listener, cert, key)
	}()

}

func GetServerAddress() string {
	return "https://" + listener.Addr().String()
}

func StopServer() {
	srv.Close()
}
