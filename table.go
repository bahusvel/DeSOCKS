package main

import (
	"encoding/binary"
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

func SplitHost(hostPort string) (string, int64) {
	portIndex := strings.Index(hostPort, ":")
	if portIndex == -1 {
		return hostPort, -1
	}
	dstport, err := strconv.ParseInt(hostPort[portIndex+1:], 10, 16)
	if err != nil {
		panic(err)
	}
	return hostPort[:portIndex], dstport
}

func (this *Connection) ParseHTTPHeader(appData string) bool {
	host := ""
	var port int64
	if strings.HasPrefix(appData, "CONNECT") {
		this.Url = URLFromMethod(appData, "CONNECT")
		host, port = SplitHost(this.Url)
		this.DstPort = layers.TCPPort(port)
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

	host, port = SplitHost(parsedUrl.Host)
	if port == -1 {
		this.DstPort = 80
	} else {
		this.DstPort = layers.TCPPort(port)
	}

	if err := this.ResolveHost(host); err != nil {
		log.Println("Error resolving", host, err)
		return false
	}
	return true
}

type ConnectionTable map[uint64]*Connection

func (this *ConnectionTable) ProcessPacket(packet gopacket.Packet) (*Connection, bool) {
	var key uint64
	netflow := packet.NetworkLayer().(*layers.IPv4)
	transflow := packet.TransportLayer().(*layers.TCP)

	if netflow.SrcIP.Equal(PROXY_IP) {
		key = (uint64(binary.BigEndian.Uint32(netflow.DstIP)) << 16) | uint64(transflow.DstPort)
	} else {
		key = (uint64(binary.BigEndian.Uint32(netflow.SrcIP)) << 16) | uint64(transflow.SrcPort)
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
		// FIXME this may leak, handshake size needs to be limited
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
