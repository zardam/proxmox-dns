package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/Telmate/proxmox-api-go/proxmox"
	"github.com/miekg/dns"
)

var ttl int
var ipPrefix, bind string
var insecure *bool

func main() {
	flag.IntVar(&ttl, "ttl", 3600, "Time to live")
	flag.StringVar(&ipPrefix, "ipPrefix", "192.168.1.", "Prefix to match vm IP")
	insecure = flag.Bool("insecure", true, "TLS insecure mode")
	flag.StringVar(&bind, "bind", ":53", "Bind address:port")
	flag.Parse()

	startDNSandWait()
}

func startDNSandWait() {
	dns.HandleFunc(".", handleRequest)
	go func() {
		srv := &dns.Server{Addr: bind, Net: "udp"}
		err := srv.ListenAndServe()
		if err != nil {
			log.Fatalf("Unable to start udp listener: %s", err.Error())
		}
	}()
	go func() {
		srv := &dns.Server{Addr: bind, Net: "tcp"}
		err := srv.ListenAndServe()
		if err != nil {
			log.Fatalf("Unable to start TCP listener: %s", err.Error())
		}
	}()
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		log.Printf("%s received, exiting", sig)
		done <- true
	}()
	log.Print("Started")
	<-done
}

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	domain := r.Question[0].Name
	log.Printf("Handling request for '%s'", domain)
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	vmName := strings.Split(domain, ".")[0]
	ip, err := findIpAddress(vmName)
	if err == nil {
		log.Printf("Found '%s' for vm '%s'", ip.String(), vmName)
		rr := new(dns.A)
		rr.Hdr = dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: uint32(ttl)}
		rr.A = ip
		m.Answer = []dns.RR{rr}
	} else {
		log.Print(err)
	}
	w.WriteMsg(m)
}

func findIpAddress(vmName string) (ip net.IP, err error) {
	tlsconf := &tls.Config{InsecureSkipVerify: true}
	if !*insecure {
		tlsconf = nil
	}
	c, err := proxmox.NewClient(os.Getenv("PM_API_URL"), nil, tlsconf, 10)
	if err != nil {
		return nil, err
	}
	err = c.Login(os.Getenv("PM_USER"), os.Getenv("PM_PASS"), "")
	if err != nil {
		return nil, err
	}
	vmid, err := c.GetVmRefByName(vmName)
	if err != nil {
		intVmid, err := strconv.Atoi(vmName)
		if err != nil {
			return nil, err
		}
		vmid = proxmox.NewVmRef(intVmid)
	}
	networkInterfaces, err := c.GetVmAgentNetworkInterfaces(vmid)
	if err != nil {
		return nil, err
	}

	for _, networkInterface := range networkInterfaces {
		for _, ipAddress := range networkInterface.IPAddresses {
			if strings.HasPrefix(ipAddress.String(), ipPrefix) {
				return ipAddress, nil
			}
		}
	}

	return nil, fmt.Errorf("no IP address for '%s' found", vmName)
}
