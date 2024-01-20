package tests

import (
	"main/tunnel"
	"testing"
)

func TestRunCommand(test *testing.T) {
	expectedOutput := "hello world!"
	outputWithNewLine := tunnel.RunCommand("echo", expectedOutput)
	output := outputWithNewLine[:len(outputWithNewLine)-1]
	if output != expectedOutput {
		test.Fatalf("echo command output doesn't match expected: %s != %s", output, expectedOutput)
	}
}

func TestFindInterfaceByIP(test *testing.T) {
	loopbackExpected := "lo"
	test.Logf("exists loopback interface with name: %s", loopbackExpected)

	loopbackFound, err := tunnel.FindInterfaceByIP("127.0.0.1")
	if err != nil {
		test.Fatalf("interface for ip 127.0.0.1 not found: %v", err)
	}
	test.Logf("found loopback interface with name: %s", loopbackFound)

	if loopbackFound != loopbackExpected {
		test.Fatalf("found loopback doesn't match expected: %s != %s", loopbackFound, loopbackExpected)
	}
}
