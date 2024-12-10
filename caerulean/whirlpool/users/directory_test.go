package users

import (
	"context"
	"crypto/rand"
	"main/generated"
	"main/tunnel"
	"main/utils"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	DIRECTORY_CYCLE_MTU          = "1500"
	DIRECTORY_CYCLE_NAME         = "testtun"
	DIRECTORY_CYCLE_VIRIDIAN_UID = "test_user_uid"
)

func TestDirectoryCycle(test *testing.T) {
	test.Setenv("SEASIDE_TUNNEL_MTU", DIRECTORY_CYCLE_MTU)
	test.Setenv("SEASIDE_TUNNEL_NAME", DIRECTORY_CYCLE_NAME)

	tunnelConfig := tunnel.Preserve()
	err := tunnelConfig.Open()
	if err != nil {
		test.Fatalf("Error establishing network connections: %v", err)
	}

	base, cancel := context.WithCancel(context.Background())
	ctx := tunnel.NewContext(base, tunnelConfig)

	dict := NewViridianDict(ctx)

	viridianKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(viridianKey); err != nil {
		test.Fatalf("symmetrical key reading error: %v", err)
	}

	viridianUID := DIRECTORY_CYCLE_VIRIDIAN_UID
	generationTime := time.Now().UTC()
	viridianToken := generated.UserToken{
		Uid:          viridianUID,
		Session:      viridianKey,
		Privileged:   true,
		Subscription: timestamppb.New(generationTime),
	}
	test.Logf("viridian will be added: %v", viridianToken.String())

	viridianInternalAddress := net.IP{127, 0, 0, 1}
	viridianGatewayAddress := net.IP{192, 168, 0, 1}
	viridianPort := uint16(12345)
	test.Logf("viridian additional params: address: %v, gateway: %v, port: %d", viridianInternalAddress, viridianGatewayAddress, viridianPort)

	viridianID, err := dict.Add(ctx, &viridianToken, viridianInternalAddress, viridianGatewayAddress, viridianPort)
	if err != nil {
		test.Fatalf("error adding viridian: %v", err)
	}
	test.Logf("ID of viridian added: %v", *viridianID)

	if utils.IsSpecialIPAddress(*viridianID) {
		test.Fatalf("error generating viridian number (it matches special IP address): %d", *viridianID)
	}

	viridian, ok := dict.Get(*viridianID)
	if !ok {
		test.Fatalf("error getting added viridian: %v", viridian)
	}
	test.Logf("viridian added: %v", viridian)

	if !viridian.timeout.Before(time.Now().UTC()) {
		test.Fatalf("incorrect viridian overtime value: %v >= %v", viridian.timeout, time.Now().UTC())
	}

	if !net.IP.Equal(viridian.Address, viridianInternalAddress) {
		test.Fatalf("viridian address doesn't match provided: %v != %v", viridian.Address, viridianInternalAddress)
	}

	if viridian.UID != viridianUID {
		test.Fatalf("viridian UID doesn't match provided: %v != %v", viridian.UID, viridianUID)
	}

	err = dict.Update(*viridianID, int32(100))
	if err != nil {
		test.Fatalf("error updating viridian: %v", err)
	}

	dict.Delete(*viridianID, false)

	deletedViridian, ok := dict.Get(*viridianID)
	if ok {
		test.Fatalf("error getting deleted viridian: %v", deletedViridian)
	}

	dict.Clear()

	cancel()
	tunnelConfig.Close()
}
