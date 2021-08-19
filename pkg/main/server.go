package main

//Awfully written - don't look, or you go blind...

import (
	"context"
	"net/http"
)

var srv http.Server

func StartSever(key, cert string) {
	srv = http.Server{Addr: ":8443"}
	go func() {
		srv.ListenAndServeTLS(cert, key)
	}()

}

func StopServer() {
	srv.Shutdown(context.TODO())
}