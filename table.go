package main

import (
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"

	"github.com/google/gopacket"
)

type Connection struct {
	SrcIP   string
	SrcPort string
	Url     *url.URL
	DstIP   string
	DstPort string
}

func (this *Connection) ParseUrl() error {
	portIndex := strings.Index(this.Url.Host, ":")
	host := ""
	if portIndex == -1 {
		host = this.Url.Host
	} else {
		host = this.Url.Host[:portIndex]
	}
	ip, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		return err
	}
	this.DstIP = ip.String()
	return nil
}

func URLFromMethod(appData string, method string) string {
	noMethod := appData[len(method+" "):]
	index := strings.Index(noMethod, " ")
	if index == -1 {
		return ""
	}
	return noMethod[:index]
}

func (this *Connection) ParseHTTPHeader(appData string) bool {
	rawUrl := ""
	if strings.HasPrefix(appData, "CONNECT") {
		rawUrl = URLFromMethod(appData, "CONNECT")
	} else if strings.HasPrefix(appData, "GET") {
		rawUrl = URLFromMethod(appData, "GET")
	} else if strings.HasPrefix(appData, "POST") {
		rawUrl = URLFromMethod(appData, "POST")
	} else {
		return false
	}
	parsedUrl, err := url.Parse(rawUrl)
	if err != nil {
		return false
	}
	this.Url = parsedUrl
	if err := this.ParseUrl(); err != nil {
		log.Println("Error resolving", this.Url, err)
	}
	return true
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
		if !connection.ParseHTTPHeader(contents) {
			return nil
		}
		connection.SrcIP = netflow.Src().String()
		connection.SrcPort = transflow.Src().String()
		fmt.Printf("%+v\n", connection)
		(*this)[key] = connection
	}
	return connection
}
