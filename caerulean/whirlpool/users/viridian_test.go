package users

import (
	"main/crypto"
	"main/generated"
	"net"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestViridianCycle(test *testing.T) {
	_, viridianKey, err := crypto.GenerateCipher()
	if err != nil {
		test.Fatalf("error generating viridian cipher: %v", err)
	}

	viridianUID := "test_user_uid"
	generationTime := time.Now().UTC()
	viridianToken := generated.UserToken{
		Uid:        viridianUID,
		Session:    viridianKey,
		Privileged: true,
		Subscription: &timestamppb.Timestamp{
			Seconds: int64(generationTime.Second()),
			Nanos:   int32(generationTime.Nanosecond()),
		},
	}
	test.Logf("viridian will be added: %v", viridianToken.String())

	viridianInternalAddress := net.IP{127, 0, 0, 1}
	viridianGatewayAddress := net.IP{192, 168, 0, 1}
	viridianPort := uint32(12345)
	test.Logf("viridian additional params: address: %v, gateway: %v, port: %d", viridianInternalAddress, viridianGatewayAddress, viridianPort)

	viridianID, createStatus, err := AddViridian(&viridianToken, viridianInternalAddress, viridianGatewayAddress, viridianPort)
	if err != nil {
		test.Fatalf("error adding viridian: %v, status %d", err, createStatus)
	}
	test.Logf("ID of viridian added: %v", *viridianID)

	expectedViridianID := uint16(2)
	if *viridianID != expectedViridianID {
		test.Fatalf("error generating viridian number: %d != %d", *viridianID, expectedViridianID)
	}

	viridian := GetViridian(*viridianID)
	if viridian == nil {
		test.Fatalf("error getting added viridian: %v", viridian)
	}
	test.Logf("viridian added: %v", viridian)

	if !isViridianOvertime(viridian) {
		test.Fatalf("incorrect viridian overtime value for timeout: %v", viridian.timeout)
	}

	if !net.IP.Equal(viridian.Address, viridianInternalAddress) {
		test.Fatalf("viridian address doesn't match provided: %v != %v", viridian.Address, viridianInternalAddress)
	}

	if viridian.UID != viridianUID {
		test.Fatalf("viridian UID doesn't match provided: %v != %v", viridian.UID, viridianUID)
	}

	updateStatus, err := UpdateViridian(*viridianID, int32(100))
	if err != nil {
		test.Fatalf("error updating viridian: %v, status %d", err, updateStatus)
	}

	DeleteViridian(*viridianID, false)

	deletedViridian := GetViridian(*viridianID)
	if deletedViridian != nil {
		test.Fatalf("error getting deleted viridian: %v", deletedViridian)
	}
}
