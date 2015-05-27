package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var verbose int
var hostNameRewrite map[string]string

type connectionRequestPartOneSocks5 struct {
	Version     uint8
	Command     uint8
	Null2       uint8
	AddressType uint8
}

type connectionRequestResponseSocks5 struct {
	Version     uint8
	Status      uint8
	Null        uint8
	AddressType uint8
	Address     [4]byte
	Port        [2]byte
}

const (
	connectTimeout  = 30 * time.Second
	echoBufferBytes = 1024
)

func echoLoop(toRead net.Conn, toWrite net.Conn, wg *sync.WaitGroup) {
	var buffer [echoBufferBytes]byte
	for {
		n, err := toRead.Read(buffer[0:])
		if err != nil {
			break
		}
		if verbose >= 3 {
			log.Printf("%s", string(buffer[0:]))
		}
		_, err = toWrite.Write(buffer[0:n])
		if err != nil {
			break
		}
	}
	toWrite.Close()
	wg.Done()
}

func writeConnectionResponseSocks5(client net.Conn, response connectionRequestResponseSocks5) error {
	if err := binary.Write(client, binary.BigEndian, response); err != nil {
		log.Printf("binary.Write failed: %+v [%T]", err, response)
		return err
	}
	return nil
}

func resolveServerSocks5(client net.Conn, request connectionRequestPartOneSocks5) (net.IP, []byte, uint8, []byte, error) {
	var serverIP net.IP
	var address []byte
	var dnsLength uint8
	var rewritten bool
	port := make([]byte, 2)
	if request.AddressType == 1 {
		// IPv4
		address = make([]byte, 4)
		if err := binary.Read(client, binary.BigEndian, &address); err != nil {
			return serverIP, address, dnsLength, port, err
		}
		if err := binary.Read(client, binary.BigEndian, &port); err != nil {
			return serverIP, address, dnsLength, port, err
		}
		serverIP = net.IP(address[0:])
	} else if request.AddressType == 3 {
		// DNS
		if err := binary.Read(client, binary.BigEndian, &dnsLength); err != nil {
			return serverIP, address, dnsLength, port, err
		}
		address = make([]byte, dnsLength)
		if err := binary.Read(client, binary.BigEndian, &address); err != nil {
			return serverIP, address, dnsLength, port, err
		}
		if err := binary.Read(client, binary.BigEndian, &port); err != nil {
			return serverIP, address, dnsLength, port, err
		}
		v, e := hostNameRewrite[string(address[0:])]
		if e {
			ips, err := net.LookupIP(v)
			if err != nil {
				return serverIP, address, dnsLength, port, err
			}
			if verbose >= 2 {
				log.Printf("Found IPS for %s: %+v", v, ips)
			}
			serverIP = ips[0]
			rewritten = true
		} else {
			ips, err := net.LookupIP(string(address[0:]))
			if err != nil {
				return serverIP, address, dnsLength, port, err
			}
			if verbose >= 2 {
				log.Printf("Found IPS for %s: %+v", string(address[0:]), ips)
			}
			serverIP = ips[0]
		}
		// TODO randomize
	} else if request.AddressType == 4 {
		// IPv6
		address = make([]byte, 16)
		if err := binary.Read(client, binary.BigEndian, &address); err != nil {
			return serverIP, address, dnsLength, port, err
		}
		if err := binary.Read(client, binary.BigEndian, &port); err != nil {
			return serverIP, address, dnsLength, port, err
		}
		serverIP = net.IP(address[0:])
	} else {
		return serverIP, address, dnsLength, port, fmt.Errorf("Invalid address type requested by client: %x", request.AddressType)
	}
	if verbose >= 2 {
		if request.AddressType == 3 {
			if rewritten {
				log.Printf("%s requested %+v. Rewriting IP address %s", client.RemoteAddr(), string(address), serverIP)
			} else {
				log.Printf("%s requested %+v. Using IP address %s", client.RemoteAddr(), string(address), serverIP)
			}
		} else {
			log.Printf("%s requested %+v", client.RemoteAddr(), serverIP)
		}
	}
	return serverIP, address, dnsLength, port, nil
}

func handleSocks5(client net.Conn) error {
	var authMethodCount uint8
	var authMethods []uint8
	var authCanNoAuth bool
	var serverIP net.IP
	var serverAddr string
	var Err error
	port := make([]byte, 2)
	if err := binary.Read(client, binary.BigEndian, &authMethodCount); err != nil {
		return err
	}
	authMethods = make([]uint8, authMethodCount)
	if err := binary.Read(client, binary.BigEndian, &authMethods); err != nil {
		return err
	}
	for _, v := range authMethods {
		if v == 0 {
			authCanNoAuth = true
		}
	}
	if false == authCanNoAuth {
		return errors.New("Client does not support 'No authentication' and no auth protocols yet implimented")
	}
	if err := binary.Write(client, binary.BigEndian, []uint8{5, 0}); err != nil {
		return err
	}

	request := connectionRequestPartOneSocks5{}
	if err := binary.Read(client, binary.BigEndian, &request); err != nil {
		return err
	}
	if serverIP, _, _, port, Err = resolveServerSocks5(client, request); Err != nil {
		return Err
	}

	portInt := binary.BigEndian.Uint16(port)
	isV4 := serverIP.To4()
	if isV4 != nil {
		serverAddr = fmt.Sprintf("%s:%d", serverIP, portInt)
	} else {
		serverAddr = fmt.Sprintf("[%s]:%d", serverIP, portInt)
	}

	response := connectionRequestResponseSocks5{}
	response.Version = 5
	response.Status = 0
	response.AddressType = 1

	server, err := net.DialTimeout("tcp", serverAddr, connectTimeout)
	if err != nil {
		// General Failure
		response.Status = 1
	}

	if err := writeConnectionResponseSocks5(client, response); err != nil {
		return err
	}

	if response.Status != 0 {
		return err
	}
	defer server.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go echoLoop(server, client, &wg)
	go echoLoop(client, server, &wg)
	wg.Wait()

	return nil
}

func handleConnection(client net.Conn) error {
	defer client.Close()

	var version uint8
	if err := binary.Read(client, binary.BigEndian, &version); err != nil {
		return err
	}

	if version == 5 {
		return handleSocks5(client)
	}

	return errors.New("Invalid Version in Handshake")
}

func main() {

	var listenAddress string
	var rewrite string

	flag.IntVar(&verbose, "verbose", 0, "Verbosity level (0: off, 1: some, 2: everything)")
	flag.StringVar(&listenAddress, "listen", "127.0.0.1:8888", "ip:port string on which the proxy should listen")
	flag.StringVar(&rewrite, "rewrite", "", "hostfrom1:hostto1[,hostfrom2:hostto2[...]]")

	flag.Parse()

	hostNameRewrite = map[string]string{}

	if rewrite != "" {
		for _, v := range strings.Split(rewrite, ",") {
			translate := strings.SplitN(v, ":", 2)
			if len(translate) != 2 {
				continue
			}
			hostNameRewrite[translate[0]] = translate[1]
		}
	}

	if verbose >= 3 {
		log.Printf("Rewrite Rules: %+v", hostNameRewrite)
	}

	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not listen on", listenAddress)
		os.Exit(1)
	}
	if verbose >= 1 {
		log.Printf("Socks5 Proxy Listening on %s", listenAddress)
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error from listen port:", err)
			os.Exit(1)
		}
		go func() {
			if verbose >= 1 {
				log.Printf("New connection from %s to %s", conn.RemoteAddr(), conn.LocalAddr())
			}
			if err := handleConnection(conn); err != nil {
				fmt.Println("Error:", err)
			}
		}()
	}
}
