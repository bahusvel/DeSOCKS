package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/google/gopacket"
)

type Connection struct {
	SrcIP    string
	SrcPort  string
	Domain   string
	Endpoint string
	DstIP    string
	DstPort  string
}

func (this *Connection) ParseEndpoint() error {
	index := strings.Index(this.Endpoint, ":")
	if index == -1 {
		return errors.New("Port not found")
	}
	this.DstPort = this.Endpoint[index+1:]
	this.Domain = this.Endpoint[:index]
	ip, err := net.ResolveIPAddr("ip4", this.Domain)
	if err != nil {
		return err
	}
	this.DstIP = ip.String()
	return nil
}

type ConnectionTable map[string]*Connection

func (this *ConnectionTable) ProcessPacket(packet gopacket.Packet) *Connection {
	key := ""
	netflow := packet.NetworkLayer().NetworkFlow()
	transflow := packet.TransportLayer().TransportFlow()
	if netflow.Src().String() == PROXY_IP {
		key = netflow.Dst().String()
		key += ":" + transflow.Dst().String()
	} else {
		key = netflow.Src().String()
		key += ":" + transflow.Src().String()
	}
	connection, ok := (*this)[key]
	if !ok && netflow.Src().String() == PROXY_IP {
		return nil
	}
	if !ok {
		connection = &Connection{}
		appLayer := packet.ApplicationLayer()
		if appLayer == nil {
			return nil
		}
		contents := string(appLayer.LayerContents())
		if !strings.HasPrefix(contents, "CONNECT ") {
			return nil
		}
		noConnect := contents[len("CONNECT "):]
		index := strings.Index(noConnect, " ")
		if index == -1 {
			return nil
		}
		connection.Endpoint = noConnect[:index]
		if err := connection.ParseEndpoint(); err != nil {
			log.Println("Error resolving", connection.Endpoint, err)
		}
		connection.SrcIP = netflow.Src().String()
		connection.SrcPort = transflow.Src().String()
		fmt.Printf("%+v\n", connection)
		(*this)[key] = connection
	}
	return connection
}
