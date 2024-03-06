package tunnel

import (
	"net"
	"testing"
)

func TestRunCommand(test *testing.T) {
	expectedOutput := "hello world!"
	outputWithNewLine := runCommand("echo", expectedOutput)
	output := outputWithNewLine[:len(outputWithNewLine)-1]
	if output != expectedOutput {
		test.Fatalf("echo command output doesn't match expected: %s != %s", output, expectedOutput)
	}
}

func TestFindInterfaceByIP(test *testing.T) {
	loopbackExpected, err := net.InterfaceByName("lo")
	if err != nil {
		test.Fatalf("loopback interface not found: %v", err)
	}
	test.Logf("exists loopback interface with name: %s", loopbackExpected.Name)

	loopbackFound, err := findInterfaceByIP("127.0.0.1")
	if err != nil {
		test.Fatalf("interface for ip 127.0.0.1 not found: %v", err)
	}
	test.Logf("found loopback interface with name: %s", loopbackFound.Name)

	if loopbackFound.Name != loopbackExpected.Name {
		test.Fatalf("found loopback doesn't match expected: %s != %s", loopbackFound.Name, loopbackExpected.Name)
	}
}
