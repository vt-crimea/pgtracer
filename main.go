package main

import (
	"container/list"
	"log"
	"os"
	"pgtracer/database"
	"pgtracer/pgparser"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func getMessageQueue(clients *map[string]*pgparser.MessageQueue, ip, port string) *pgparser.MessageQueue {
	ipPort := ip + ":" + port
	res := (*clients)[ipPort]
	if res == nil {
		res = &(pgparser.MessageQueue{Ip: ip, Port: port})
		(*clients)[ipPort] = res
		//очередь сообщений
		res.Messages = *list.New()
		res.Messages.Init()
	}
	return res
}

func resetMessageQueue(clients *map[string]*pgparser.MessageQueue, ip, port string) {
	ipPort := ip + ":" + port
	res := (*clients)[ipPort]
	if res != nil {
		res.Id = 0
		res.Messages.Init()
	}
}

func getPortFromConnectionString(str string) string {
	arr := strings.Split(str, " ")
	for _, s := range arr {
		s = strings.ToLower(s)
		if strings.Contains(s, "port") {
			res := strings.Split(s, "=")
			return res[1]
		}
	}
	return "5432" //default
}

func getParamFromOSArgs(par string) string {
	for i, arg := range os.Args {
		//log.Println(arg)
		if strings.ToLower(arg) == par {
			if len(os.Args) < i+2 {
				break
			}
			return os.Args[i+1]
		}
	}

	return ""
	/*
		params := strings.Join(os.Args, " ")

		for _, ch := range params {
			log.Println(ch)
		}
	*/
}

func main() {
	var (
		handle  *pcap.Handle
		err     error
		clients map[string]*pgparser.MessageQueue
		ownPort string = ""

		dbConnection   string = getParamFromOSArgs("-db")
		ip2Listen      string = getParamFromOSArgs("-iplisten")
		ipFilter       string = getParamFromOSArgs("-ipfilter")
		pgPort         string = getParamFromOSArgs("-pgport")
		deviceTolisten string
	)

	//находим сетевой интерфейс по айпишнику из параметров
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("error retrieving devices - %v", err)
	}

	for _, device := range devices {
		if strings.Contains(strings.ToLower(device.Name), "loopback") && ip2Listen == "127.0.0.1" {
			deviceTolisten = device.Name
			break
		}
		for _, iaddress := range device.Addresses {
			if iaddress.IP.String() == ip2Listen {
				deviceTolisten = device.Name
				break
			}
		}
	}
	if deviceTolisten == "" {
		log.Fatal("network interface not found!")
	}

	err = database.Connect(dbConnection)
	if err != nil {
		log.Println("No connection to database: ", err)
	} else {
		log.Println("Database connection ok")
	}
	//если порт не указали напрямую, берем его из настроек бд
	if pgPort == "" {
		pgPort = getPortFromConnectionString(dbConnection)
	}

	err = database.CreateTables()
	if err != nil {
		log.Println("Error creating table or schema: ", err)
	}

	go func() {
		time.Sleep(time.Second)
		database.Test()
	}()

	clients = make(map[string]*pgparser.MessageQueue)

	//if handle, err = pcap.OpenLive("\\Device\\NPF_{E71C2DBE-D567-465D-B9D3-E464AB6D2C71}", 1600, true, pcap.BlockForever); err != nil {
	//"\\Device\\NPF_Loopback"
	if handle, err = pcap.OpenLive(deviceTolisten, 65535, true, pcap.BlockForever); err != nil {
		panic(err)
	}
	if err := handle.SetBPFFilter("tcp and port " + pgPort); err != nil { // optional
		panic(err)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	log.Println("Capture started")

	isStarted := false

	for packet := range packetSource.Packets() {
		appLayer := packet.ApplicationLayer()
		transportLayer := packet.TransportLayer()
		networkLayer := packet.NetworkLayer()

		ipFrom := networkLayer.NetworkFlow().Src().String()
		portFrom := transportLayer.TransportFlow().Src().String()

		ipTo := networkLayer.NetworkFlow().Dst().String()
		portTo := transportLayer.TransportFlow().Dst().String()

		if portFrom == ownPort || portTo == ownPort {
			continue
		}
		_ = ipTo
		_ = ipFrom
		_ = portFrom
		_ = clients
		if appLayer != nil {

			data := (appLayer.Payload())

			if portTo == pgPort {
				//запрос

				//отсекаем "свои" запросы
				if strings.Contains(string(data), "pgtracer") || strings.Contains(string(data), "pg_") {
					ownPort = portFrom
					continue
				}
				//отсекаем по фильтру
				if ipFilter != "" && ipFrom != ipFilter {
					continue
				}

				if pgparser.IsQueryStart(data[0]) {
					isStarted = true
					resetMessageQueue(&clients, ipFrom, portFrom)
				}
				if isStarted {
					isStarted = true
					//log.Println("raw query: ", string(data), " ", portFrom)
					//log.Println("raw query (byte): ", data)
					queue := getMessageQueue(&clients, ipFrom, portFrom)
					queue.ParseMessages(data)
				}
			} else {
				//ответ

				//отсекаем по фильтру
				if ipFilter != "" && ipTo != ipFilter {
					continue
				}

				if isStarted {
					//log.Println("raw answer: ", string(data))
					//log.Println("raw answer (byte): ", data)

					queue := getMessageQueue(&clients, ipTo, portTo)
					queue.ParseAnswerMessages(data)
				}
				_ = 0
			}
		}

	}
}
