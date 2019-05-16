package radius

import (
	"fmt"
	"net"
	"sync"
	"time"
)

const AUTH_PORT = 1812
const ACCOUNTING_PORT = 1813

type Server struct {
	addr      string
	secret    string
	service   Service
	ch        chan struct{}
	waitGroup *sync.WaitGroup
	cl        *ClientList
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

// NewServer return a new Server given a addr, secret, and service
func NewServer(addr string, secret string, service Service) *Server {
	s := &Server{addr: addr,
		secret:    secret,
		service:   service,
		ch:        make(chan struct{}),
		waitGroup: &sync.WaitGroup{},
	}
	return s
}

// WithClientList set a list of clients that have it's own secret
func (s *Server) WithClientList(cl *ClientList) {
	s.cl = cl
}

/*
func (s *Server) RegisterService(serviceAddr string, handler Service) {
	s.services[serviceAddr] = handler
}
*/

// ListenAndServe listen on the UDP network address
func (s *Server) ListenAndServe() error {
	addr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	for {
		select {
		case <-s.ch:
			return nil
		default:
		}
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		b := make([]byte, 4096)
		n, addr, err := conn.ReadFrom(b)
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
				continue
			}
			return err
		}

		s.waitGroup.Add(1)
		go func(p []byte, addr net.Addr) {
			defer s.waitGroup.Done()
			var secret = s.secret

			if s.cl != nil {
				host, _, err := net.SplitHostPort(addr.String())
				if err != nil {
					fmt.Println("[pac.Host]", err)
					return
				}
				if cl := s.cl.Get(host); cl != nil {
					secret = cl.GetSecret()
				}
			}

			pac, err := DecodePacket(secret, p)
			if err != nil {
				fmt.Println("[pac.Decode]", err)
				return
			}
			pac.ClientAddr = addr.String()

			npac := s.service.RadiusHandle(pac)
			err = npac.Send(conn, addr)
			if err != nil {
				fmt.Println("[npac.Send]", err)
			}
		}(b[:n], addr)
	}
}

// Stop will stop the server
func (s *Server) Stop() {
	close(s.ch)
	s.waitGroup.Wait()
}
