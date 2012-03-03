package main

import ("github.com/jessta/radius"
"net"

"fmt"
)

func main(){
 addr, err :=  net.ResolveUDPAddr("udp", ":1812")
	if err != nil {
		panic(err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		panic(err)
	}
	var b [512]byte
	for {
		n,addr,err := conn.ReadFrom(b[:]) 
		if err != nil {
			panic(err)
		}	
		p := b[:n]
		pac := new(radius.Packet)
		pac.Code = radius.PacketCode(p[0])
		pac.Identifier = p[1]
		copy(pac.Authenticator[:],p[4:20])
		npac := new(radius.Packet)
		npac.Code = radius.AccessReject
		npac.Identifier = pac.Identifier
		npac.AVPs = append(npac.AVPs,radius.AVP{radius.ReplyMessage,  []byte("you dick!")} )
		fmt.Println("request auth:",pac.Authenticator)
		ra := npac.ResponseAuth(pac.Authenticator)
		fmt.Println("response auth:",ra)
		copy(npac.Authenticator[:],ra)
		var buf [512]byte
		n,_, err = npac.Encode(buf[:])
		if err != nil {
			panic(err)
		}
		n,err = conn.WriteTo(buf[:n],addr)
			if err != nil {
			panic(err)
		}
		fmt.Println(pac,addr)
		fmt.Println(npac,addr)
		fmt.Println("sent:",buf[:n])
		fmt.Println("reponse Auth:", buf[4:20])
		fmt.Println(n)
	}
}
