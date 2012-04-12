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
		err = pac.Decode(p)
		if err != nil {
			panic(err)
		}		
		user:= pac.Attributes(radius.UserName)
		pass := pac.Attributes(radius.UserPassword)

		
		npac := pac.Reply()
		if len(user) == 1 && len(pass) == 1{
			if err := radius.Authenticate(string(user[0].Value),string(pass[0].Value)); err == nil {
				npac.Code = radius.AccessAccept
			} else {
				npac.Code = radius.AccessReject
				fmt.Println("user:",string(user[0].Value)," pass:",string(pass[0].Value))
			}
		}else {
			npac.Code = radius.AccessReject
				fmt.Println("user:",string(user[0].Value)," pass:",string(pass[0].Value))

		}
		npac.AVPs = append(npac.AVPs, radius.AVP{radius.ReplyMessage, []byte("you dick!")})
		fmt.Println("request auth:", pac.Authenticator)
		npac.Send(conn, addr)
	}
}
