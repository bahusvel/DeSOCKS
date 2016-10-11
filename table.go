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
	Url     string
	DstIP   string
	DstPort string
}

func (this *Connection) ParseUrl(host string) error {
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
	if strings.HasPrefix(appData, "CONNECT") {
		this.Url = URLFromMethod(appData, "CONNECT")
		host := ""
		portIndex := strings.Index(this.Url, ":")
		if portIndex == -1 {
			return false
		}
		host = this.Url[:portIndex]
		this.DstPort = this.Url[portIndex+1:]
		if err := this.ParseUrl(host); err != nil {
			log.Println("Error resolving", host, err)
		}
		return true
	} else if strings.HasPrefix(appData, "GET") {
		this.Url = URLFromMethod(appData, "GET")
	} else if strings.HasPrefix(appData, "POST") {
		this.Url = URLFromMethod(appData, "POST")
	} else {
		return false
	}
	parsedUrl, err := url.Parse(this.Url)
	if err != nil {
		return false
	}
	host := ""
	portIndex := strings.Index(parsedUrl.Host, ":")
	if portIndex == -1 {
		host = parsedUrl.Host
		this.DstPort = "80"
	} else {
		host = parsedUrl.Host[:portIndex]
		this.DstPort = parsedUrl.Host[portIndex+1:]
	}

	if err := this.ParseUrl(host); err != nil {
		log.Println("Error resolving", host, err)
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
