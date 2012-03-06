package main

import (
	"github.com/jessta/radius"
	"net"
	"fmt"
)

func main() {
	addr, err := net.ResolveUDPAddr("udp", ":1812")
	if err != nil {
		panic(err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		panic(err)
	}
	var b [512]byte
	for {
		n, addr, err := conn.ReadFrom(b[:])
		if err != nil {
			panic(err)
		}
		p := b[:n]
		pac := new(radius.Packet)
		pac.Code = radius.PacketCode(p[0])
		pac.Identifier = p[1]
		copy(pac.Authenticator[:], p[4:20])

		npac := pac.Reply()
		npac.Code = radius.AccessReject

		npac.AVPs = append(npac.AVPs, radius.AVP{radius.ReplyMessage, []byte("you dick!")})
		fmt.Println("request auth:", pac.Authenticator)
		npac.Send(conn, addr)
	}
}
