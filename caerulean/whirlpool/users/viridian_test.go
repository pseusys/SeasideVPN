package users

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestViridianOvertime(test *testing.T) {
	hourAgo := time.Now().Add(-time.Hour)

	viridian := &Viridian{
		admin:   false,
		timeout: &hourAgo,
	}
	if !viridian.isViridianOvertime() {
		test.Fatalf("viridian with timeout %v is not overtime at %v", viridian.timeout, time.Now())
	}

	admin := &Viridian{
		admin:   true,
		timeout: &hourAgo,
	}
	if admin.isViridianOvertime() {
		test.Fatalf("admin with timeout %v is overtime at %v", viridian.timeout, time.Now())
	}
}

func TestViridianStop(test *testing.T) {
	_, cancel := context.WithCancel(context.Background())

	address, err := net.ResolveUDPAddr("udp4", "127.0.0.1:0")
	if err != nil {
		test.Fatalf("error resolving local address: %v", err)
	}

	connection, err := net.ListenUDP("udp4", address)
	if err != nil {
		test.Fatalf("error resolving connection (%s): %v", address.String(), err)
	}

	deletionTimer := time.AfterFunc(time.Hour, func() {})
	viridian := &Viridian{
		reset:         deletionTimer,
		CancelContext: cancel,
		SeaConn:       connection,
	}

	viridian.stop()

	r, err := viridian.SeaConn.Read(make([]byte, 64))
	if err == nil && r != 0 {
		test.Fatalf("reading from closed connection succeeded")
	}
}
