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

func openConnection(address string) *net.UDPConn {
	gateway, err := net.ResolveUDPAddr(UDP, address)
	if err != nil {
		log.Fatal(err)
	}

	connection, err := net.ListenUDP(UDP, gateway)
	if err != nil {
		log.Fatal(err)
	}

	return connection
}

func ReceivePacketsFromViridian(tunnel *water.Interface) {
	buf := make([]byte, BUFFERSIZE)

	connection := openConnection(fmt.Sprintf("%s:%d", *ip, *input))
	defer connection.Close()

	for {
		r, addr, err := connection.ReadFromUDP(buf)
		if err != nil || r == 0 {
			log.Println("Reading from UDP error: ", err)
			continue
		}

		header, err := ipv4.ParseHeader(buf[:r])
		if err != nil {
			log.Println("Parsing UDP header error: ", err)
			continue
		}

		log.Printf("Received %d bytes from viridian %v: %+v\n", r, addr, header)

		s, err := tunnel.Write(buf[:r])
		if err != nil || s == 0 {
			log.Println("Writing to tunnel error: ", err)
			continue
		}
	}
}

func SendPacketsToViridian(tunnel *water.Interface) {
	packet := make([]byte, BUFFERSIZE)

	connection := openConnection(fmt.Sprintf("%s:%d", *ip, *output))
	defer connection.Close()

	for {
		r, err := tunnel.Read(packet)
		if err != nil || r == 0 {
			log.Println("Reading from tunnel error: ", err)
			continue
		}

		header, _ := ipv4.ParseHeader(packet[:r]) // TODO: handle bigger packets
		if err != nil {
			log.Println("Parsing tunnel header error: ", err)
			continue
		}

		gateway, err := net.ResolveUDPAddr(UDP, fmt.Sprintf("%s:%v", header.Dst.String(), OUTPUT_PORT))
		if err != nil {
			log.Fatal(err)
		}

		log.Printf("Sending %d bytes to viridian (%+v): %+v (%+v)\n", r, gateway, header, err)

		s, err := connection.WriteToUDP(packet[:r], gateway)
		if err != nil || s == 0 {
			log.Println("Writing to UDP error: ", err)
			continue
		}
	}
}
