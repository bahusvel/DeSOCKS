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

const (
	STATE_SYN         = iota
	STATE_ESTABLISHED = iota
	STATE_CLOSED      = iota
)

type Connection struct {
	SrcIP     net.IP
	SrcPort   layers.TCPPort
	Url       string
	DstIP     net.IP
	DstPort   layers.TCPPort
	State     int
	Handshake []gopacket.Packet
}

func (this *Connection) String() string {
	return fmt.Sprintf("Connection: (%s:%d)->(%s:%d) STATE=%d", this.SrcIP.String(), this.SrcPort, this.DstIP.String(), this.DstPort, this.State)
}

func (this *Connection) ResolveHost(host string) error {
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
	//HACK nil is here because of the bug in gopacket
	if ipLayer.SrcIP.Equal(PROXY_IP) || ipLayer.SrcIP == nil {
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
		if err := this.ResolveHost(host); err != nil {
			log.Println("Error resolving", host, err)
			return false
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

	if err := this.ResolveHost(host); err != nil {
		log.Println("Error resolving", host, err)
		return false
	}
	return true
}

type ConnectionTable map[string]*Connection

func (this *ConnectionTable) ProcessPacket(packet gopacket.Packet) (*Connection, bool) {
	key := ""
	netflow := packet.NetworkLayer().(*layers.IPv4)
	transflow := packet.TransportLayer().(*layers.TCP)

	if netflow.SrcIP.Equal(PROXY_IP) {
		key = netflow.DstIP.String()
		key += ":" + transflow.DstPort.String()
	} else {
		key = netflow.SrcIP.String()
		key += ":" + transflow.SrcPort.String()
	}
	connection, ok := (*this)[key]
	if !ok {
		connection = &Connection{}
		connection.SrcIP = netflow.SrcIP
		connection.SrcPort = transflow.SrcPort
		connection.State = STATE_SYN
		(*this)[key] = connection
	}
	if connection.State == STATE_SYN {
		connection.Handshake = append(connection.Handshake, packet)
		//fmt.Println("Appending handshake", packet)
	}
	if transflow.FIN || transflow.RST {
		connection.State = STATE_CLOSED
	}
	if connection.State == STATE_SYN && !netflow.SrcIP.Equal(PROXY_IP) {
		appLayer := packet.ApplicationLayer()
		if appLayer == nil {
			return nil, false
		}
		contents := string(appLayer.LayerContents())
		if !connection.ParseHTTPHeader(contents) {
			return nil, false
		}
		connection.State = STATE_ESTABLISHED
		connection.Handshake = connection.Handshake[:len(connection.Handshake)-1]
		//fmt.Printf("%+v\n%v\n", connection, connection.Handshake)
		fmt.Printf("%+v\n", connection)
		return connection, true
	}

	return connection, false
}
