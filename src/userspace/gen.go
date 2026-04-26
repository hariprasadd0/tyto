package main

//go:generate go tool bpf2go -tags linux tyto ../xdp/tyto_xdp.c -- -I/usr/include/x86_64-linux-gnu
