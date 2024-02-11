package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"go.sazak.io/intro-ebpf/0x03-packet-count/server"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go ebpf xdp.c

var (
	ifaceName  = flag.String("iface", "", "network interface to attach XDP program to")
	serverPort = flag.String("port", "8080", "port for the WS server to listen on")
)

type IPMetadata struct {
	SrcIP   netip.Addr
	SrcPort uint16
	DstPort uint16
}

func (t *IPMetadata) UnmarshalBinary(data []byte) (err error) {
	if len(data) != 8 {
		return fmt.Errorf("invalid data length: %d", len(data))
	}
	if err = t.SrcIP.UnmarshalBinary(data[4:8]); err != nil {
		return
	}
	t.SrcPort = uint16(data[3])<<8 | uint16(data[2])
	t.DstPort = uint16(data[1])<<8 | uint16(data[0])
	return nil
}

func (t IPMetadata) String() string {
	return fmt.Sprintf("%s:%d => :%d", t.SrcIP, t.SrcPort, t.DstPort)
}

type PacketCounts map[string]int

func (i PacketCounts) String() string {
	var keys []string
	for k := range i {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(fmt.Sprintf("%s\t| %d\n", k, i[k]))
	}

	return sb.String()
}

func main() {
	log.SetPrefix("packet_count: ")
	log.SetFlags(log.Ltime | log.Lshortfile)

	flag.Parse()
	validateFlags()

	// Subscribe to signals for terminating the program.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	iface, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		log.Fatalf("network iface lookup for %q: %s", *ifaceName, err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := ebpfObjects{}
	if err := loadEbpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgFunc,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	srv, err := server.New(server.WithPort(*serverPort))
	if err != nil {
		log.Fatalf("creating server: %s", err)
	}
	srv.Start()

	// Print the contents of the BPF hash map (source IP address -> packet count).
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			if err := objs.XdpStatsMap.Close(); err != nil {
				log.Fatalf("closing map reader: %s", err)
			}
			return
		case <-ticker.C:
			m, err := parsePacketCounts(objs.XdpStatsMap)
			if err != nil {
				log.Printf("Error reading map: %s", err)
				continue
			}
			log.Printf("Map contents:\n%s", m)
			srv.Submit(m)
		}
	}
}

func parsePacketCounts(m *ebpf.Map) (PacketCounts, error) {
	var (
		key    IPMetadata
		val    uint32
		counts = make(PacketCounts)
	)
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		counts[key.String()] = int(val)
	}
	return counts, iter.Err()
}

func validateFlags() {
	if *ifaceName == "" {
		log.Fatal("Please provide a network interface name with -iface")
	}
}
