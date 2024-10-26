package main

import (
	"fmt"
	"net"
	"net/http"
	"sync"
	"tinyproxy/internal/server/compression"
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
	server := &http.Server{
		Addr:    ":8080",
		Handler: http.HandlerFunc(compression.Compress(handler)),
	}

	ln, err := net.Listen("tcp", server.Addr)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Listening on %s\n", server.Addr)
	server.Serve(ln)
}
