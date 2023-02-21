package main

import (
	"fmt"
	"pgtracer/pgparser"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	var (
		handle *pcap.Handle
		query  pgparser.PGQuery = pgparser.PGQuery{}
		err    error
	)
	/*
		devices, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatalf("error retrieving devices - %v", err)
		}

		for _, device := range devices {
			fmt.Printf("Device Name: %s\n", device.Name)
			fmt.Printf("Device Description: %s\n", device.Description)
			fmt.Printf("Device Flags: %d\n", device.Flags)
			for _, iaddress := range device.Addresses {
				fmt.Printf("\tInterface IP: %s\n", iaddress.IP)
				fmt.Printf("\tInterface NetMask: %s\n", iaddress.Netmask)
			}
		}
	*/

	pgPort := "5433"
	//if handle, err = pcap.OpenLive("\\Device\\NPF_{E71C2DBE-D567-465D-B9D3-E464AB6D2C71}", 1600, true, pcap.BlockForever); err != nil {
	if handle, err = pcap.OpenLive("\\Device\\NPF_Loopback", 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	}
	if err := handle.SetBPFFilter("tcp and port " + pgPort); err != nil { // optional
		panic(err)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	fmt.Println("connected")
	for packet := range packetSource.Packets() {
		appLayer := packet.ApplicationLayer()

		if appLayer != nil {
			data := (appLayer.Payload())

			if packet.TransportLayer().TransportFlow().Src().String() != pgPort {
				//запрос
				fmt.Println("received data: ", data)
				fmt.Println("received data: ", string(data))

				if pgparser.IsQueryStart(data[0]) {
					query = pgparser.PGQuery{}
				} else {
					_ = 0
					//fmt.Println("received: ", data)
					//fmt.Println("received (str): ", string(data))
				}
				query.ParsePacket(data)
			} else {
				//ответ
				//fmt.Println("sent data: ", data)
				//fmt.Println("sent data (str): ", string(data))
				_ = 0
			}
		}

	}
}
