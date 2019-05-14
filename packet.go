package radius

import (
	"crypto"
	"crypto/hmac"
	_ "crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
)

var ErrMessageAuthenticatorCheckFail = fmt.Errorf("RADIUS Response-Authenticator verification failed")

type Packet struct {
	Secret        string
	Code          PacketCode
	Identifier    uint8
	Authenticator [16]byte
	AVPs          []AVP
	ClientAddr    string
}

func (p *Packet) Copy() *Packet {
	outP := &Packet{
		Secret:        p.Secret,
		Code:          p.Code,
		Identifier:    p.Identifier,
		Authenticator: p.Authenticator, //这个应该是拷贝
	}
	outP.AVPs = make([]AVP, len(p.AVPs))
	for i := range p.AVPs {
		outP.AVPs[i] = p.AVPs[i].Copy()
	}
	return outP
}

//此方法保证不修改包的内容
//This method does not modify the contents of the package to ensure
func (p *Packet) Encode() (b []byte, err error) {
	p = p.Copy()
	p.SetAVP(AVP{
		Type:  MessageAuthenticator,
		Value: make([]byte, 16),
	})
	if p.Code == AccessRequest {
		_, err := rand.Read(p.Authenticator[:])
		if err != nil {
			return nil, err
		}
	}
	//TODO request的时候重新计算密码
	// When the password request recalculation
	b, err = p.encodeNoHash()
	if err != nil {
		return
	}
	//计算Message-Authenticator,Message-Authenticator被放在最后面
	//Calculation Message-Authenticator, Message-Authenticator is placed in the rearmost
	hasher := hmac.New(crypto.MD5.New, []byte(p.Secret))
	hasher.Write(b)
	copy(b[len(b)-16:len(b)], hasher.Sum(nil))

	// fix up the authenticator
	// handle request and response stuff.
	// here only handle response part.
	switch p.Code {
	case AccessRequest:
	case DisconnectRequest, DisconnectAccept, DisconnectReject:
		fallthrough
	case AccessAccept, AccessReject, AccessChallenge, AccountingRequest, AccountingResponse:
		//rfc2865 page 15 Response Authenticator
		//rfc2866 page 6 Response Authenticator
		//rfc2866 page 6 Request Authenticator
		hasher := crypto.Hash(crypto.MD5).New()
		hasher.Write(b)
		hasher.Write([]byte(p.Secret))
		copy(b[4:20], hasher.Sum(nil))
	default:
		return nil, fmt.Errorf("not handle p.Code %d", p.Code)
	}

	return b, err
}

func (p *Packet) encodeNoHash() (b []byte, err error) {
	b = make([]byte, 4096)
	b[0] = uint8(p.Code)
	b[1] = uint8(p.Identifier)
	copy(b[4:20], p.Authenticator[:])
	written := 20
	bb := b[20:]
	for i, _ := range p.AVPs {
		n, err := p.AVPs[i].Encode(bb)
		written += n
		if err != nil {
			return nil, err
		}
		bb = bb[n:]
	}
	binary.BigEndian.PutUint16(b[2:4], uint16(written))
	return b[:written], nil
}

func (p *Packet) HasAVP(attrType AttributeType) bool {
	for i, _ := range p.AVPs {
		if p.AVPs[i].Type == attrType {
			return true
		}
	}
	return false
}

//get one avp
func (p *Packet) GetAVP(attrType AttributeType) *AVP {
	for i := range p.AVPs {
		if p.AVPs[i].Type == attrType {
			return &p.AVPs[i]
		}
	}
	return nil
}

//get one vsa
func (p *Packet) GetVSA(vendor uint32, attr uint8) *VSA {
	for i := range p.AVPs {
		if p.AVPs[i].Type == VendorSpecific {
			a := p.AVPs[i]
			vsa := new(VSA)
			value := a.Value
			vsa.Vendor = binary.BigEndian.Uint32(value[0:4])
			vsa.Type = uint8(value[4])
			vsa.Value = make([]byte, value[5]-2)
			copy(vsa.Value, value[6:])
			if vsa.Type == attr && vsa.Vendor == vendor {
				return vsa
			}
		}
	}
	return nil
}

//set one avp,remove all other same type
func (p *Packet) SetAVP(avp AVP) {
	p.DeleteOneType(avp.Type)
	p.AddAVP(avp)
}

func (p *Packet) AddAVP(avp AVP) {
	p.AVPs = append(p.AVPs, avp)
}

func (p *Packet) AddVSA(vsa VSA) {
	p.AddAVP(vsa.ToAVP())
}

//删除一个AVP
//Delete a AVP
func (p *Packet) DeleteAVP(avp *AVP) {
	for i := range p.AVPs {
		if &(p.AVPs[i]) == avp {
			for j := i; j < len(p.AVPs)-1; j++ {
				p.AVPs[j] = p.AVPs[j+1]
			}
			p.AVPs = p.AVPs[:len(p.AVPs)-1]
			break
		}
	}
	return
}

//delete all avps with this type
func (p *Packet) DeleteOneType(attrType AttributeType) {
	for i := 0; i < len(p.AVPs); i++ {
		if p.AVPs[i].Type == attrType {
			for j := i; j < len(p.AVPs)-1; j++ {
				p.AVPs[j] = p.AVPs[j+1]
			}
			p.AVPs = p.AVPs[:len(p.AVPs)-1]
			i--
			break
		}
	}
	return
}

func (p *Packet) Reply() *Packet {
	pac := new(Packet)
	pac.Authenticator = p.Authenticator
	pac.Identifier = p.Identifier
	pac.Secret = p.Secret
	return pac
}

func (p *Packet) Send(c net.PacketConn, addr net.Addr) error {
	buf, err := p.Encode()
	if err != nil {
		return err
	}

	_, err = c.WriteTo(buf, addr)
	return err
}

func DecodePacket(Secret string, buf []byte) (p *Packet, err error) {
	if len(buf) < 20 {
		return nil, errors.New("invalid length")
	}
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
	//验证Message-Authenticator,并且通过测试验证此处算法是正确的
	//Verify Message-Authenticator, and tested to verify the algorithm is correct here
	err = p.checkMessageAuthenticator()
	if err != nil {
		return p, err
	}
	return p, nil
}

//如果没有MessageAuthenticator也算通过
//If no Message Authenticator can be considered by
func (p *Packet) checkMessageAuthenticator() (err error) {
	Authenticator := p.GetAVP(MessageAuthenticator)
	if Authenticator == nil {
		return nil
	}
	AuthenticatorValue := Authenticator.Value
	defer func() { Authenticator.Value = AuthenticatorValue }()
	Authenticator.Value = make([]byte, 16)
	content, err := p.encodeNoHash()
	if err != nil {
		return err
	}
	hasher := hmac.New(crypto.MD5.New, []byte(p.Secret))
	hasher.Write(content)
	if !hmac.Equal(hasher.Sum(nil), AuthenticatorValue) {
		return ErrMessageAuthenticatorCheckFail
	}
	return nil
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
	if avp == nil {
		return ""
	}
	return avp.Decode(p).(string)
}
func (p *Packet) GetPassword() (password string) {
	avp := p.GetAVP(UserPassword)
	if avp == nil {
		return ""
	}
	return avp.Decode(p).(string)
}

func (p *Packet) GetNasIpAddress() (ip net.IP) {
	avp := p.GetAVP(NASIPAddress)
	if avp == nil {
		return nil
	}
	return avp.Decode(p).(net.IP)
}

func (p *Packet) GetAcctStatusType() AcctStatusTypeEnum {
	avp := p.GetAVP(AcctStatusType)
	if avp == nil {
		return AcctStatusTypeEnum(0)
	}
	return avp.Decode(p).(AcctStatusTypeEnum)
}

func (p *Packet) GetAcctSessionId() string {
	avp := p.GetAVP(AcctSessionId)
	if avp == nil {
		return ""
	}
	return avp.Decode(p).(string)
}

func (p *Packet) GetAcctTotalOutputOctets() uint64 {
	out := uint64(0)
	avp := p.GetAVP(AcctOutputOctets)
	if avp != nil {
		out += uint64(avp.Decode(p).(uint32))
	}
	avp = p.GetAVP(AcctOutputGigawords)
	if avp != nil {
		out += uint64(avp.Decode(p).(uint32)) << 32
	}
	return out
}

func (p *Packet) GetAcctTotalInputOctets() uint64 {
	out := uint64(0)
	avp := p.GetAVP(AcctInputOctets)
	if avp != nil {
		out += uint64(avp.Decode(p).(uint32))
	}
	avp = p.GetAVP(AcctInputGigawords)
	if avp != nil {
		out += uint64(avp.Decode(p).(uint32)) << 32
	}
	return out
}

// it is ike_id in strongswan client
func (p *Packet) GetNASPort() uint32 {
	avp := p.GetAVP(NASPort)
	if avp == nil {
		return 0
	}
	return avp.Decode(p).(uint32)
}

func (p *Packet) GetNASIdentifier() string {
	avp := p.GetAVP(NASIdentifier)
	if avp == nil {
		return ""
	}
	return avp.Decode(p).(string)
}

func (p *Packet) GetEAPMessage() *EapPacket {
	avp := p.GetAVP(EAPMessage)
	if avp == nil {
		return nil
	}
	return avp.Decode(p).(*EapPacket)
}

func (p *Packet) GetFramedIPAddress() (ip net.IP) {
	avp := p.GetAVP(FramedIPAddress)
	if avp == nil {
		return nil
	}
	return avp.Decode(p).(net.IP)
}

func (p *Packet) GetTerminateCause() string {
	avp := p.GetAVP(AcctTerminateCause)
	if avp == nil {
		return ""
	}
	return avp.Decode(p).(string)
}

func (p *Packet) GetCallingStationId() string {
	avp := p.GetAVP(CallingStationId)
	if avp == nil {
		return ""
	}
	return avp.Decode(p).(string)
}

func (p *Packet) GetCalledStationId() string {
	avp := p.GetAVP(CalledStationId)
	if avp == nil {
		return ""
	}
	return avp.Decode(p).(string)
}

func (p *Packet) GetNASPortId() string {
	avp := p.GetAVP(NASPortId)
	if avp == nil {
		return ""
	}
	return avp.Decode(p).(string)
}
