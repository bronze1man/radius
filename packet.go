package radius
import (
	"errors"
	//"bytes"
	"encoding/binary"
	"fmt"
	"crypto"
	_ "crypto/md5"
	//"io"

)
const AUTH_PORT = 1812
const ACCOUNTING_PORT = 1813

type PacketCode uint8

const (
	AccessRequest      PacketCode = 1
	AccessAccept       PacketCode = 2
	AccessReject       PacketCode = 3
	AccountingRequest  PacketCode = 4
	AccountingResponse PacketCode = 5
	AccessChallenge    PacketCode = 11
	StatusServer       PacketCode = 12 //(experimental)
	StatusClient       PacketCode = 13 //(experimental)
	Reserved           PacketCode = 255
)

type AttributeType uint8

const (
	_                                    = iota //drop the zero
	UserName               AttributeType = iota
	UserPassword           AttributeType = iota
	CHAPPassword           AttributeType = iota
	NASIPAddress           AttributeType = iota
	NASPort                AttributeType = iota
	ServiceType            AttributeType = iota
	FramedProtocol         AttributeType = iota
	FramedIPAddress        AttributeType = iota
	FramedIPNetmask        AttributeType = iota
	FramedRouting          AttributeType = iota
	FilterId               AttributeType = iota
	FramedMTU              AttributeType = iota
	FramedCompression      AttributeType = iota
	LoginIPHost            AttributeType = iota
	LoginService           AttributeType = iota
	LoginTCPPort           AttributeType = iota
	_                                    = iota //17 unassigned
	ReplyMessage           AttributeType = iota
	CallbackNumber         AttributeType = iota
	CallbackId             AttributeType = iota
	_                                    = iota //21 unassigned
	FramedRoute            AttributeType = iota
	FramedIPXNetwork       AttributeType = iota
	State                  AttributeType = iota
	Class                  AttributeType = iota
	VendorSpecific         AttributeType = iota
	SessionTimeout         AttributeType = iota
	IdleTimeout            AttributeType = iota
	TerminationAction      AttributeType = iota
	CalledStationId        AttributeType = iota
	CallingStationId       AttributeType = iota
	NASIdentifier          AttributeType = iota
	ProxyState             AttributeType = iota
	LoginLATService        AttributeType = iota
	LoginLATNode           AttributeType = iota
	LoginLATGroup          AttributeType = iota
	FramedAppleTalkLink    AttributeType = iota
	FramedAppleTalkNetwork AttributeType = iota
	FramedAppleTalkZone    AttributeType = iota
	AcctStatusType         AttributeType = iota
	AcctDelayTime          AttributeType = iota
	AcctInputOctets        AttributeType = iota
	AcctOutputOctets       AttributeType = iota
	AcctSessionId          AttributeType = iota
	AcctAuthentic          AttributeType = iota
	AcctSessionTime        AttributeType = iota
	AcctInputPackets       AttributeType = iota
	AcctOutputPackets      AttributeType = iota
	AcctTerminateCause     AttributeType = iota
	AcctMultiSessionId     AttributeType = iota
	AcctLinkCount          AttributeType = iota
	// 52 to 59 reserved for accounting)
	CHAPChallenge AttributeType = 60
	NASPortType   AttributeType = 61
	PortLimit     AttributeType = 62
	LoginLATPort  AttributeType = 63
)

type Packet struct {
	Code         PacketCode
	Identifier   uint8
	//length uint16
	Authenticator [16]byte
	AVPs         []AVP
}

type AVP struct {
	Type   AttributeType
	Value  []byte
}

func (p Packet)Encode(b []byte)(n int, ret []byte, err error){
	b[0] = uint8(p.Code)
	b[1] = uint8(p.Identifier)
	copy(b[4:20],p.Authenticator[:])
	written := 20
	bb := b[20:]
	for i,_ := range p.AVPs {
		n,err = p.AVPs[i].Encode(bb)
		written += n
		if err != nil {
			return written,nil, err
		}
		bb = bb[n:]
		fmt.Println("written:", written)
	}
	//check if written too big.
	binary.BigEndian.PutUint16(b[2:4],uint16(written))
	return written,b,err
}

func (a AVP)Encode(b []byte)(n int ,err error){
	fullLen := len(a.Value)+2 //type and length
	if fullLen > 255 || fullLen < 2{
		return 0,errors.New("value too big for attribute")
	}
	b[0] = uint8(a.Type)
	b[1] =  uint8(fullLen)
	copy(b[2:],a.Value)
	return fullLen, err	
}

func (a AttributeType) String() string {
	switch a {
	case UserName:
		return "Username"
	case UserPassword:
		return "UserPassword"
	case CHAPPassword:
		return "CHAPPassword"
	case NASIPAddress:
		return "NASIPAddress"
	case NASPort:
		return "NASPort"
	case ServiceType:
		return "ServiceType"
	case FramedProtocol:
		return "FramedProtocol"
	case FramedIPAddress:
		return "FramedIPAddress"
	case FramedIPNetmask:
		return "FramedIPNetmask"
	case FramedRouting:
		return "FramedRouting"
	case FilterId:
		return "FilterId"
	case FramedMTU:
		return "FramedMTU"
	case FramedCompression:
		return "FramedCompression"
	case LoginIPHost:
		return "LoginIPHost"
	case LoginService:
		return "LoginService"
	case LoginTCPPort:
		return "LoginTCPPort"
	case 17:
		return "unassigned 17"
	case ReplyMessage:
		return "ReplyMessage"
	case CallbackNumber:
		return "CallbackNumber"
	case CallbackId:
		return "CallbackId"
	case 21:
		return "unassigned 21"
	case FramedRoute:
		return "FramedRoute"
	case FramedIPXNetwork:
		return "FramedIPXNetwork"
	case State:
		return "State"
	case Class:
		return "Class"
	case VendorSpecific:
		return "VendorSpecific"
	case SessionTimeout:
		return "SessionTimeout"
	case IdleTimeout:
		return "IdleTimeout"
	case TerminationAction:
		return "TerminationAction"
	case CalledStationId:
		return "CalledStationId"
	case CallingStationId:
		return "CallingStationId"
	case NASIdentifier:
		return "NASIdentifier"
	case ProxyState:
		return "ProxyState"
	case LoginLATService:
		return "LoginLATService"
	case LoginLATNode:
		return "LoginLATNode"
	case LoginLATGroup:
		return "LoginLATGroup"
	case FramedAppleTalkLink:
		return "FramedAppleTalkLink"
	case FramedAppleTalkNetwork:
		return "FramedAppleTalkNetwork"
	case FramedAppleTalkZone:
		return "FramedAppleTalkZone"
	case AcctStatusType:
		return "AcctStatusType"
	case AcctDelayTime:
		return "AcctDelayTime"
	case AcctInputOctets:
		return "AcctInputOctets"
	case AcctOutputOctets:
		return "AcctOutputOctets"
	case AcctSessionId:
		return "AcctSessionId"
	case AcctAuthentic:
		return "AcctAuthentic"
	case AcctSessionTime:
		return "AcctSessionTime"
	case AcctInputPackets:
		return "AcctInputPackets"
	case AcctOutputPackets:
		return "AcctOutputPackets"
	case AcctTerminateCause:
		return "AcctTerminateCause"
	case AcctMultiSessionId:
		return "AcctMultiSessionId"
	case AcctLinkCount:
		return "AcctLinkCount"
	case 52, 53, 54, 55, 56, 57, 58, 59:
		return "ReservedForAccounting"
	case CHAPChallenge:
		return "CHAPChallenge"
	case NASPortType:
		return "NASPortType"
	case PortLimit:
		return "PortLimit"
	case LoginLATPort:
		return "LoginLATPort"
	}
	return "unknown attribute type"
}

func (p PacketCode) String() string {
	switch p {
	case AccessRequest:
		return "AccessRequest"
	case AccessAccept:
		return "AccessAccept"
	case AccessReject:
		return "AccessReject"
	case AccountingRequest:
		return "AccountingRequest"
	case AccountingResponse:
		return "AccountingResponse"
	case AccessChallenge:
		return "AccessChallenge"
	case StatusServer:
		return "StatusServer"
	case StatusClient:
		return "StatusClient"
	case Reserved:
		return "Reserved"
	}
	return "unknown packet code"
}

func (p Packet) Has(attrType AttributeType) (bool) {
	for i,_:= range p.AVPs {
		if p.AVPs[i].Type == attrType {
			return true
		}
	}
	return false
}

func (p Packet) Valid() bool {
	switch p.Code {
	case AccessRequest:
		if !(p.Has(NASIPAddress) || p.Has(NASIdentifier)) {
			return false
		}

		if p.Has(CHAPPassword) && p.Has(UserPassword){
			return false
		}
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



func (p Packet)ResponseAuth(requestAuth [16]byte) []byte {
	var buf [4096]byte
	p.Authenticator = requestAuth
	n,_,err := p.Encode(buf[:])
	if err!= nil {
		panic(err)
	}
	b := buf[:n]
	b = append(b,"s3cr3t"...)
	hasher := crypto.Hash(crypto.MD5).New()
	hasher.Write(b)
	copy(p.Authenticator[:], hasher.Sum(nil))
	fmt.Println("md5 sum:", hasher.Sum(nil))
	return hasher.Sum(nil)
         //MD5(Code+ID+Length+RequestAuth+Attributes+Secret)
}