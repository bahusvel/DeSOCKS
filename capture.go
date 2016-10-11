package main

// Use tcpdump to create a test file
// tcpdump -w test.pcap
// or use the example above for writing pcap files

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const (
	PROXY_IP   = "133.243.18.8"
	PROXY_PORT = "3128"
)

var (
	pcapFile string = "NICTProxy.dmp"
)

func main() {
	table := ConnectionTable{}

	// Open file instead of device
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	proxybpf, err := handle.NewBPF(fmt.Sprintf("host %s and port %s", PROXY_IP, PROXY_PORT))
	if err != nil {
		log.Fatal("Could not generate BPF", err)
	}

	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	count := 0
	for packet := range packetSource.Packets() {
		/*
			if count == 50 {
				return
			}
		*/
		if proxybpf.Matches(packet.Metadata().CaptureInfo, packet.Data()) {
			connection := table.ProcessPacket(packet)
			if connection != nil {
				//fmt.Printf("CONNECTION:%+v\n%v\n", connection, packet)
			}
		}

		count++
	}
}
