package main

import (
	"fmt"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/gopacket/layers"

	"github.com/google/gopacket"
)

type Connection struct {
	SrcIP   net.IP
	SrcPort layers.TCPPort
	Url     string
	DstIP   net.IP
	DstPort layers.TCPPort
}

func (this *Connection) ParseUrl(host string) error {
	ip, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		return err
	}
	this.DstIP = ip.IP
	return nil
}

func (this *Connection) RewritePacket(packet gopacket.Packet) []byte {
	linklayer := packet.LinkLayer().(*layers.Ethernet)
	ipLayer := packet.NetworkLayer().(*layers.IPv4)
	tcpLayer := packet.TransportLayer().(*layers.TCP)
	appLayer := packet.ApplicationLayer()
	if ipLayer.SrcIP.String() == PROXY_IP {
		ipLayer.SrcIP = this.DstIP
		tcpLayer.SrcPort = this.DstPort
	} else {
		ipLayer.DstIP = this.DstIP
		tcpLayer.DstPort = this.DstPort
	}
	buf := gopacket.NewSerializeBuffer()
	if appLayer != nil {
		gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, linklayer, ipLayer, tcpLayer, gopacket.Payload(tcpLayer.LayerPayload()))
	} else {
		gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, linklayer, ipLayer, tcpLayer)
	}

	return buf.Bytes()
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
		dstport, _ := strconv.ParseInt(this.Url[portIndex+1:], 10, 16)
		this.DstPort = layers.TCPPort(uint16(dstport))
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
		this.DstPort = 80
	} else {
		host = parsedUrl.Host[:portIndex]
		dstport, _ := strconv.ParseInt(this.Url[portIndex+1:], 10, 16)
		this.DstPort = layers.TCPPort(uint16(dstport))
	}

	if err := this.ParseUrl(host); err != nil {
		log.Println("Error resolving", host, err)
	}
	return true
}

type ConnectionTable map[string]*Connection

func (this *ConnectionTable) ProcessPacket(packet gopacket.Packet) *Connection {
	key := ""
	netflow := packet.NetworkLayer().(*layers.IPv4)
	transflow := packet.TransportLayer().(*layers.TCP)
	if netflow.SrcIP.String() == PROXY_IP {
		key = netflow.DstIP.String()
		key += ":" + transflow.DstPort.String()
	} else {
		key = netflow.SrcIP.String()
		key += ":" + transflow.SrcPort.String()
	}
	connection, ok := (*this)[key]
	if !ok && netflow.SrcIP.String() == PROXY_IP {
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
		connection.SrcIP = netflow.SrcIP
		connection.SrcPort = transflow.SrcPort
		fmt.Printf("%+v\n", connection)
		(*this)[key] = connection
	}
	return connection
}
