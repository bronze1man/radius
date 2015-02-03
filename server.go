package radius

import (
	"fmt"
	"net"
)

const AUTH_PORT = 1812
const ACCOUNTING_PORT = 1813

type Server struct {
	addr    string
	secret  string
	service Service
	//services map[string]Service
}

type Service interface {
	RadiusHandle(request *Packet) *Packet
}

type PasswordService struct{}

func (p *PasswordService) Authenticate(request *Packet) (*Packet, error) {
	npac := request.Reply()
	npac.Code = AccessReject
	npac.AVPs = append(npac.AVPs, AVP{Type: ReplyMessage, Value: []byte("you dick!")})
	return npac, nil
}
func NewServer(addr string, secret string, service Service) *Server {
	return &Server{addr: addr,
		secret:  secret,
		service: service}
}

/*
func (s *Server) RegisterService(serviceAddr string, handler Service) {
	s.services[serviceAddr] = handler
}
*/

func (s *Server) ListenAndServe() error {
	addr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}

	for {
		b := make([]byte, 4096)
		n, addr, err := conn.ReadFrom(b)
		if err != nil {
			return err
		}
		go func(p []byte, addr net.Addr) {
			//fmt.Printf("DecodePacket %#v\n",p)
			pac, err := DecodePacket(s.secret, p)
			if err != nil {
				fmt.Println("[pac.Decode]", err)
				return
			}

			npac := s.service.RadiusHandle(pac)
			err = npac.Send(conn, addr)
			if err != nil {
				fmt.Println("[npac.Send]", err)
			}
		}(b[:n], addr)
	}
	return nil
}
