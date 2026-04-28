package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
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

func main (){
 if len(os.Args) < 2 {
 log.Fatalf("Usage: sudo ./tyto <interface>  e.g. sudo ./tyto eth0")
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

 rb,err:=ringbuf.NewReader(obj.Events)
 if err != nil {
 log.Fatalf("creating ringbuf reader: %v", err)
 }
 defer rb.Close()

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
          proto := "UNKNOWN"
          switch event.Protocol {
          case 17:
              proto = "UDP"
          case 6:
              proto = "TCP/SYN"
          case 1:
              proto = "ICMP"
          }
          fmt.Printf("[ALERT] BLOCKED %s  protocol=%s  pps=%d\n",
              intToIP(event.SrcIP), proto, event.PktCount)
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
  }
 }()

 log.Println("Tyto running. Press Ctrl+C to stop.")
 <-sig
 log.Println("Shutting down...")
}
