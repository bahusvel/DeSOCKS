package main

// Use tcpdump to create a test file
// tcpdump -w test.pcap
// or use the example above for writing pcap files

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

const (
	PROXY_PORT = "3128"
)

var (
	PROXY_IP         = net.IPv4(133, 243, 18, 8)
	readFile  string = "NICTProxy.dmp"
	writeFile string = "Rewritten.pcap"
)

func openRead() *pcap.Handle {
	handle, err := pcap.OpenOffline(readFile)
	if err != nil {
		log.Fatal(err)
	}
	return handle
}

func openWrite() (*pcapgo.Writer, *os.File) {
	// Write a new file:
	f, _ := os.Create(writeFile)
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(65536, layers.LinkTypeEthernet)
	return w, f
}

func main() {
	table := ConnectionTable{}
	// Open file instead of device
	readHandle := openRead()
	defer readHandle.Close()
	writeHandle, writeFile := openWrite()
	defer writeFile.Close()

	proxybpf, err := readHandle.NewBPF(fmt.Sprintf("host %s and port %s", PROXY_IP, PROXY_PORT))
	if err != nil {
		log.Fatal("Could not generate BPF", err)
	}

	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(readHandle, readHandle.LinkType())
	count := 0
	for packet := range packetSource.Packets() {

		if proxybpf.Matches(packet.Metadata().CaptureInfo, packet.Data()) {
			connection, established := table.ProcessPacket(packet)
			if connection != nil {
				if established {
					for _, handshakePacket := range connection.Handshake {
						//fmt.Println("Writing handshake", handshakePacket)
						rewritten := connection.RewritePacket(handshakePacket)

						writeHandle.WritePacket(handshakePacket.Metadata().CaptureInfo, rewritten)
					}
				}
				rewritten := connection.RewritePacket(packet)
				writeHandle.WritePacket(packet.Metadata().CaptureInfo, rewritten)
			}
		}
		count++
	}
	fmt.Println(table)
}
