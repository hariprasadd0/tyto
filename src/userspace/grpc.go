//go:build linux

package main

import (
	"context"

	"github.com/cilium/ebpf"
	"github.com/hariprasadd0/proto"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

type TytoGrpcServer struct {
	proto.UnimplementedTytoServer
	statsMap *ebpf.Map
	events chan *proto.TytoEvent
}

func (s *TytoGrpcServer) StreamEvents(_ *emptypb.Empty, stream grpc.ServerStreamingServer[proto.TytoEvent]) error{
	for event := range s.events {
		if err := stream.Send(event); err != nil {
			return err
		}
	}
	return nil
}

func (s *TytoGrpcServer) GetStats( ctx context.Context,_ *emptypb.Empty) (*proto.StatsResponse,error) {
	var perCpu []tytoTytoStats
	if err := s.statsMap.Lookup(uint32(0), &perCpu); err != nil {
		return nil, err
	}
	//sum all cpu stats
	var total tytoTytoStats
	for _, cpuStats := range perCpu {
	 total.TotalPackets   += cpuStats.TotalPackets
    total.DroppedPackets += cpuStats.DroppedPackets
    total.UdpDropped     += cpuStats.UdpDropped
    total.SynDropped     += cpuStats.SynDropped
    total.IcmpDropped    += cpuStats.IcmpDropped
	}

//return as proto response
return &proto.StatsResponse{
    TotalPackets:   total.TotalPackets,
    DroppedPackets: total.DroppedPackets,
    UdpDropped:     total.UdpDropped,
    SynDropped:     total.SynDropped,
    IcmpDropped:    total.IcmpDropped,
}, nil
}
