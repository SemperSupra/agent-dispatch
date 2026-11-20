//go:build ignore

// R27-K offline causal UART handshake contract probe.
// It does not configure a real QEMU serial port, and does not establish
// independent provider identity, guest ownership or kernel isolation.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const ready = "READY R27-K"
const permit = "ALLOW_B R27-K"
const receipt = "ACK R27-K"

var errRefused = errors.New("serial grant unconfirmed: keep provider UDC unbound")

// The host must not promote a mere socket Write into a guest receipt.
// All test messages use a reserved, versioned ASCII framing contract.
func host(c net.Conn, deadline time.Duration) error {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(deadline))
	reader := bufio.NewReader(c)
	first, err := reader.ReadString('\n')
	if err != nil || strings.TrimSuffix(first, "\n") != ready {
		return errRefused
	}
	if _, err = io.WriteString(c, permit+"\n"); err != nil {
		return errRefused
	}
	last, err := reader.ReadString('\n')
	if err != nil || strings.TrimSuffix(last, "\n") != receipt {
		return errRefused
	}
	return nil
}

func guest(c net.Conn, mode string) {
	defer c.Close()
	switch mode {
	case "silent":
		return
	case "wrong-ready":
		_, _ = io.WriteString(c, "READY INVALID\n")
		return
	}
	if _, err := io.WriteString(c, ready+"\n"); err != nil {
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || line != permit+"\n" {
		return
	}
	switch mode {
	case "no-ack":
		return
	case "wrong-ack":
		_, _ = io.WriteString(c, "ACK INVALID\n")
	case "valid":
		_, _ = io.WriteString(c, receipt+"\n")
	}
}

func scenario(mode string, wantAllowed bool) error {
	h, g := net.Pipe()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		guest(g, mode)
	}()
	err := host(h, 900*time.Millisecond)
	<-finished
	allowed := err == nil
	if allowed != wantAllowed {
		return fmt.Errorf("mode=%s unexpected allow=%t err=%v", mode, allowed, err)
	}
	if !allowed && !errors.Is(err, errRefused) {
		return fmt.Errorf("mode=%s did not fail closed: %v", mode, err)
	}
	return nil
}

func main() {
	for _, mode := range []string{"silent", "wrong-ready", "no-ack", "wrong-ack"} {
		if err := scenario(mode, false); err != nil {
			fmt.Println("R27_K_OFFLINE_UART_CONTRACT=RED:", err)
			panic(err)
		}
		fmt.Printf("R27_K_%s_NO_GRANT_WITHOUT_RECEIPT=PASS\n", strings.ToUpper(strings.ReplaceAll(mode, "-", "_")))
	}
	if err := scenario("valid", true); err != nil {
		fmt.Println("R27_K_OFFLINE_UART_CONTRACT=RED:", err)
		panic(err)
	}
	fmt.Println("R27_K_EXACT_READY_ALLOW_ACK_CAUSAL_CONTRACT=PASS")
	fmt.Println("R27_K_SOCKET_WRITE_IS_NOT_GUEST_RECEIPT=PASS")
	fmt.Println("R27_K_ACTUAL_QEMU_UART_RETRY_RECOVERY=NOT_TESTED")
	fmt.Println("R27_K_PROTECTED_GUEST_IDENTITY=NOT_TESTED")
}
