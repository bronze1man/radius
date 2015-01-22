package radius

import (
	"crypto"
	_ "crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
)

type Packet struct {
	Secret        string
	Code          PacketCode
	Identifier    uint8
	Authenticator [16]byte
	AVPs          []AVP
}

func (p *Packet) Encode(b []byte) (n int, err error) {
	b[0] = uint8(p.Code)
	b[1] = uint8(p.Identifier)
	copy(b[4:20], p.Authenticator[:])
	written := 20
	bb := b[20:]
	for i, _ := range p.AVPs {
		n, err = p.AVPs[i].Encode(bb)
		written += n
		if err != nil {
			return written, err
		}
		bb = bb[n:]
	}
	//check if written too big.
	binary.BigEndian.PutUint16(b[2:4], uint16(written))

	// fix up the authenticator
	// handle request and response stuff.
	// here only handle response part.
	hasher := crypto.Hash(crypto.MD5).New()
	hasher.Write(b[:written])
	hasher.Write([]byte(p.Secret))
	copy(b[4:20], hasher.Sum(nil))

	return written, err
}

func (p *Packet) HasAVP(attrType AttributeType) bool {
	for i, _ := range p.AVPs {
		if p.AVPs[i].Type == attrType {
			return true
		}
	}
	return false
}

/*
func (p *Packet) Attributes(attrType AttributeType) []*AVP {
	ret := []*AVP(nil)
	for i, _ := range p.AVPs {
		if p.AVPs[i].Type == attrType {
			ret = append(ret, &p.AVPs[i])
		}
	}
	return ret
}
*/

//get one avp
func (p *Packet) GetAVP(attrType AttributeType) AVP {
	for i, _ := range p.AVPs {
		if p.AVPs[i].Type == attrType {
			return p.AVPs[i]
		}
	}
	return AVP{}
}

/*
func (p *Packet) Valid() bool {
	switch p.Code {
	case AccessRequest:
		if !(p.Has(NASIPAddress) || p.Has(NASIdentifier)) {
			return false
		}

		if p.Has(CHAPPassword) && p.Has(UserPassword) {
			return false
		}
		return true
	case AccessAccept:
		return true
	case AccessReject:
		return true
	case AccountingRequest:
		return true
	case AccountingResponse:
		return true
	case AccessChallenge:
		return true
	case StatusServer:
		return true
	case StatusClient:
		return true
	case Reserved:
		return true
	}
	return true
}
*/

func (p *Packet) Reply() *Packet {
	pac := new(Packet)
	pac.Authenticator = p.Authenticator
	pac.Identifier = p.Identifier
	pac.Secret = p.Secret
	return pac
}

func (p *Packet) Send(c net.PacketConn, addr net.Addr) error {
	var buf [4096]byte
	n, err := p.Encode(buf[:])
	if err != nil {
		return err
	}

	n, err = c.WriteTo(buf[:n], addr)
	return err
}

func DecodePacket(Secret string, buf []byte) (p *Packet, err error) {
	p = &Packet{Secret: Secret}
	p.Code = PacketCode(buf[0])
	p.Identifier = buf[1]
	copy(p.Authenticator[:], buf[4:20])
	//read attributes
	b := buf[20:]
	for len(b) >= 2 {
		length := uint8(b[1])
		if int(length) > len(b) {
			return nil, errors.New("invalid length")
		}
		attr := AVP{}
		attr.Type = AttributeType(b[0])
		attr.Value = append(attr.Value, b[2:length]...)
		p.AVPs = append(p.AVPs, attr)
		b = b[length:]
	}
	return p, nil
}

func (p *Packet) String() string {
	s := "Code: " + p.Code.String() + "\n" +
		"Identifier: " + strconv.Itoa(int(p.Identifier)) + "\n" +
		"Authenticator: " + fmt.Sprintf("%#v", p.Authenticator) + "\n"
	for _, avp := range p.AVPs {
		s += avp.StringWithPacket(p) + "\n"
	}
	return s
}

func (p *Packet) GetUsername() (username string) {
	avp := p.GetAVP(UserName)
	if avp.IsZero() {
		return ""
	}
	return avp.Decode(p).(string)
}
func (p *Packet) GetPassword() (password string) {
	avp := p.GetAVP(UserPassword)
	if avp.IsZero() {
		return ""
	}
	return avp.Decode(p).(string)
}

func (p *Packet) GetNasIpAddress() (ip net.IP) {
	avp := p.GetAVP(NASIPAddress)
	if avp.IsZero() {
		return nil
	}
	return avp.Decode(p).(net.IP)
}

func (p *Packet) GetAcctStatusType() AcctStatusTypeEnum {
	avp := p.GetAVP(AcctStatusType)
	if avp.IsZero() {
		return AcctStatusTypeEnum(0)
	}
	return avp.Decode(p).(AcctStatusTypeEnum)
}

func (p *Packet) GetAcctSessionId() string {
	avp := p.GetAVP(AcctSessionId)
	if avp.IsZero() {
		return ""
	}
	return avp.Decode(p).(string)
}

func (p *Packet) GetAcctTotalOutputOctets() uint64 {
	out := uint64(0)
	avp := p.GetAVP(AcctOutputOctets)
	if !avp.IsZero() {
		out += uint64(avp.Decode(p).(uint32))
	}
	avp = p.GetAVP(AcctOutputGigawords)
	if !avp.IsZero() {
		out += uint64(avp.Decode(p).(uint32))*2 ^ 32
	}
	return out
}

func (p *Packet) GetAcctTotalInputOctets() uint64 {
	out := uint64(0)
	avp := p.GetAVP(AcctInputOctets)
	if !avp.IsZero() {
		out += uint64(avp.Decode(p).(uint32))
	}
	avp = p.GetAVP(AcctInputGigawords)
	if !avp.IsZero() {
		out += uint64(avp.Decode(p).(uint32))*2 ^ 32
	}
	return out
}
