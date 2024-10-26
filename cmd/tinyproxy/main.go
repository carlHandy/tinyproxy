package main

import (
	"fmt"
	"net"
	"net/http"
	"sync"
)

var bufPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 2048)
	},
}

func handler(w http.ResponseWriter, r *http.Request) {
	buf := bufPool.Get().([]byte)
	defer bufPool.Put(buf)

	fmt.Fprintf(w, "Tiny Proxy!\n")
}

func main() {
	serverr := &http.Server{
		Addr: ":8080",
		Handler: http.HandlerFunc(handler),
	}

	ln, err := net.Listen("tcp", serverr.Addr)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Listening on %s\n", serverr.Addr)
	serverr.Serve(ln)
}