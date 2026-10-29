package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

const dnsServer = "1.1.1.1:53"

func resolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 2 * time.Second}
			return d.DialContext(ctx, "udp", dnsServer)
		},
	}
}

func blocked(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err != nil {
		return true
	}
	_ = c.Close()
	return false
}

func main() {
	start := time.Now()
	r := resolver()

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	ips, err := r.LookupIP(ctx, "ip4", "example.com")
	cancel()
	if err != nil || len(ips) == 0 {
		fmt.Printf("FIRECRACKER_R2_NETWORK_ERROR stage=dns err=%q\n", fmt.Sprint(err))
		os.Exit(11)
	}

	dialer := &net.Dialer{Timeout: 4 * time.Second, Resolver: r}
	transport := &http.Transport{
		DialContext:       dialer.DialContext,
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
		DisableKeepAlives: true,
	}
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second}
	resp, err := client.Get("https://example.com/")
	if err != nil {
		fmt.Printf("FIRECRACKER_R2_NETWORK_ERROR stage=https err=%q\n", err.Error())
		os.Exit(12)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16384))
	_ = resp.Body.Close()
	if err != nil {
		fmt.Printf("FIRECRACKER_R2_NETWORK_ERROR stage=read err=%q\n", err.Error())
		os.Exit(13)
	}

	metadataBlocked := blocked("169.254.169.254:80")
	hostBlocked := blocked("192.0.2.1:80")
	tlsVersion := uint16(0)
	if resp.TLS != nil {
		tlsVersion = resp.TLS.Version
	}

	fmt.Printf(
		"FIRECRACKER_R2_NETWORK dns_ipv4=%d https_status=%d body_bytes=%d tls_version=%d metadata_blocked=%t host_blocked=%t elapsed_ms=%d\n",
		len(ips), resp.StatusCode, len(body), tlsVersion, metadataBlocked, hostBlocked, time.Since(start).Milliseconds(),
	)

	if resp.StatusCode < 200 || resp.StatusCode >= 400 || len(body) == 0 || tlsVersion < tls.VersionTLS12 || !metadataBlocked || !hostBlocked {
		os.Exit(14)
	}
}
