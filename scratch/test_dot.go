package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

func main() {
	addr := "dns.fabiseitz.de:853"
	serverName := "dns.fabiseitz.de"

	conf := &tls.Config{
		ServerName:         serverName,
		NextProtos:         []string{"dot"},
		InsecureSkipVerify: false,
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	start := time.Now()
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, conf)
	if err != nil {
		fmt.Printf("FAILED: %v\n", err)
		return
	}
	defer conn.Close()

	state := conn.ConnectionState()
	fmt.Printf("SUCCESS in %v\n", time.Since(start))
	fmt.Printf("TLS Version: %x\n", state.Version)
	fmt.Printf("ALPN Negotiated: %q\n", state.NegotiatedProtocol)
	fmt.Printf("Cipher Suite: %x\n", state.CipherSuite)
}
