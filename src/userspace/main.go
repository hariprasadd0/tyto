package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/hariprasadd0/proto"
	"google.golang.org/grpc"
)

type TytoEvent struct {
	Timestamp uint64
    SrcIP     uint32
    PktCount  uint32
    Protocol  uint8
    Pad       [3]uint8
}

func intToIP(ip uint32) string {
    return fmt.Sprintf("%d.%d.%d.%d",
        ip&0xFF,
        (ip>>8)&0xFF,
        (ip>>16)&0xFF,
        (ip>>24)&0xFF,
    )
}

func IptoUint32(ipStr string) uint32{
	ip:=net.ParseIP(ipStr).To4()
	return binary.BigEndian.Uint32(ip)
}

func main (){
 if len(os.Args) < 2 || strings.HasPrefix(os.Args[1], "--") {
 log.Fatalf("Usage: sudo ./tyto <interface> [--allow [ip]]  e.g. sudo ./tyto eth0 --allow")
 }
 ifName := os.Args[1]
 if err := rlimit.RemoveMemlock(); err != nil {
 log.Fatal(err)
 }

 obj := tytoObjects{}
 if err := loadTytoObjects(&obj, nil); err != nil {
 log.Fatal(err)
 }
 defer obj.Close()

 iface,err := net.InterfaceByName(ifName)
 if err != nil {
 log.Fatalf("interface %q not found: %v", ifName, err)
 }
 // Attach the program.
 xdpLink , err:= link.AttachXDP(link.XDPOptions{
 Program: obj.XdpProg,
 Interface: iface.Index,
 })
 if err != nil {
 log.Fatalf("could not attach XDP program: %v", err)
 }
 defer xdpLink.Close()
 log.Printf("Attached XDP program to interface %q (index %d)", ifName, iface.Index)

 if len(os.Args) > 2 && os.Args[2] == "--allow" {
     var allowIP string
     if len(os.Args) > 3 && !strings.HasPrefix(os.Args[3], "--") {
         allowIP = os.Args[3]
     } else {
         addrs, err := iface.Addrs()
         if err == nil {
             for _, addr := range addrs {
                 ipnet, ok := addr.(*net.IPNet)
                 if ok && ipnet.IP.To4() != nil {
                     allowIP = ipnet.IP.String()
                     break
                 }
             }
         }
     }
     if allowIP != "" {
         ipVal := IptoUint32(allowIP)
         val := uint8(1)
         if err := obj.AllowlistMap.Put(ipVal, val); err != nil {
             log.Printf("Failed to add allowlist for %s: %v", allowIP, err)
         } else {
             log.Printf("Allowlisted %s (0x%08x)", allowIP, ipVal)
         }
     }
 }

 rb,err:=ringbuf.NewReader(obj.Events)
 if err != nil {
 log.Fatalf("creating ringbuf reader: %v", err)
 }
 defer rb.Close()

 eventsCh := make(chan *proto.TytoEvent, 100)

 go func(){
  var event TytoEvent
  for {
  record , err := rb.Read()
  if err != nil {
  return
  }
  if err := binary.Read(
              bytes.NewBuffer(record.RawSample),
              binary.LittleEndian,
              &event,
          ); err != nil {
              continue
          }
          protoName := "UNKNOWN"
          switch event.Protocol {
          case 17:
              protoName = "UDP"
          case 6:
              protoName = "TCP/SYN"
          case 1:
              protoName = "ICMP"
          }
          fmt.Printf("[ALERT] BLOCKED %s  protocol=%s  pps=%d\n",
              intToIP(event.SrcIP), protoName, event.PktCount)
          select{
          case eventsCh <- &proto.TytoEvent{
			  Timestamp: event.Timestamp,
			  SrcIp:     event.SrcIP,
			  PktCount:  event.PktCount,
			  Protocol:  uint32(event.Protocol),
		  }:
		  default:
          }

      }
 }()
 sig := make(chan os.Signal, 1)
 signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

 go func(){
  ticker := time.NewTicker(1*time.Second)
  defer ticker.Stop()
  for range ticker.C {
  var stats []tytoTytoStats

  if err:= obj.StatsMap.Lookup(uint32(0),&stats);err!=nil{
  continue
  }
  var total tytoTytoStats
  for _,s:=range stats{
  total.TotalPackets   += s.TotalPackets
    total.DroppedPackets += s.DroppedPackets
    total.UdpDropped     += s.UdpDropped
    total.SynDropped     += s.SynDropped
    total.IcmpDropped    += s.IcmpDropped
  }
  fmt.Printf("[STATS] total=%d dropped=%d udp=%d syn=%d icmp=%d\n",
      total.TotalPackets,
      total.DroppedPackets,
      total.UdpDropped,
      total.SynDropped,
      total.IcmpDropped,
  )
  }
 }()

//grpc server
grpcServer := grpc.NewServer()
tytoSrv := &TytoGrpcServer{
    statsMap: obj.StatsMap,
    events:   eventsCh,
}
proto.RegisterTytoServer(grpcServer, tytoSrv)

lis, err := net.Listen("tcp", ":50051")
if err != nil {
    log.Fatalf("failed to listen: %v", err)
}

go func() {
    log.Println("gRPC server listening on :50051")
    if err := grpcServer.Serve(lis); err != nil {
        log.Printf("gRPC server error: %v", err)
    }
}()

 log.Println("Tyto running. Press Ctrl+C to stop.")
 <-sig
 close(eventsCh)
 grpcServer.GracefulStop()
 log.Println("Shutting down...")
}
