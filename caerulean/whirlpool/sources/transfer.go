package main

import (
	"fmt"
	"log"
	"net"

	"github.com/songgao/water"
	"golang.org/x/net/ipv4"
)

const (
	BUFFERSIZE = 2000
)

func makePublic(output *net.UDPConn, input *water.Interface) {
	buf := make([]byte, BUFFERSIZE)
	for {
		n, addr, err := output.ReadFromUDP(buf)
		header, _ := ipv4.ParseHeader(buf[:n])
		log.Printf("Received %d bytes from viridian %v: %+v\n", n, addr, header)
		if err != nil || n == 0 {
			log.Println("Error: ", err)
			continue
		}
		input.Write(buf[:n])
	}
}

func makePrivate(output *water.Interface, input *net.UDPConn) {
	packet := make([]byte, BUFFERSIZE)
	for {
		plen, err := output.Read(packet)
		if err != nil {
			break
		}
		header, _ := ipv4.ParseHeader(packet[:plen]) // TODO: handle bigger packets
		gateway, err := net.ResolveUDPAddr(UDP, fmt.Sprintf("%s:%v", header.Dst.String(), PORT))
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Sending to viridian (%+v): %+v (%+v)\n", gateway, header, err)
		input.WriteToUDP(packet[:plen], gateway)
	}
}
