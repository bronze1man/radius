package radius

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strconv"
)

type AVP struct {
	Type  AttributeType
	Value []byte
}

func (a AVP) Encode(b []byte) (n int, err error) {
	fullLen := len(a.Value) + 2 //type and length
	if fullLen > 255 || fullLen < 2 {
		return 0, errors.New("value too big for attribute")
	}
	b[0] = uint8(a.Type)
	b[1] = uint8(fullLen)
	copy(b[2:], a.Value)
	return fullLen, err
}

func (a AVP) Decode(p *Packet) interface{} {
	return getAttributeTypeDesc(a.Type).dataType.Value(p, a)
}

func (a AVP) String() string {
	return "AVP type: " + a.Type.String() + " " + getAttributeTypeDesc(a.Type).dataType.String(nil, a)
}

func (a AVP) StringWithPacket(p *Packet) string {
	return "AVP type: " + a.Type.String() + " " + getAttributeTypeDesc(a.Type).dataType.String(p, a)
}

func (a AVP) IsZero() bool {
	return int(a.Type) == 0
}

type avpDataType interface {
	Value(p *Packet, a AVP) interface{}
	String(p *Packet, a AVP) string
}

var avpString avpStringt

type avpStringt struct{}

func (s avpStringt) Value(p *Packet, a AVP) interface{} {
	return string(a.Value)
}
func (s avpStringt) String(p *Packet, a AVP) string {
	return string(a.Value)
}

var avpIP avpIPt

type avpIPt struct{}

func (s avpIPt) Value(p *Packet, a AVP) interface{} {
	return net.IP(a.Value)
}
func (s avpIPt) String(p *Packet, a AVP) string {
	return net.IP(a.Value).String()
}

var avpUint32 avpUint32t

type avpUint32t struct{}

func (s avpUint32t) Value(p *Packet, a AVP) interface{} {
	return uint32(binary.BigEndian.Uint32(a.Value))
}
func (s avpUint32t) String(p *Packet, a AVP) string {
	return strconv.Itoa(int(binary.BigEndian.Uint32(a.Value)))
}

var avpBinary avpBinaryt

type avpBinaryt struct{}

func (s avpBinaryt) Value(p *Packet, a AVP) interface{} {
	return a.Value
}
func (s avpBinaryt) String(p *Packet, a AVP) string {
	return fmt.Sprintf("%#v", a.Value)
}

var avpPassword avpPasswordt

type avpPasswordt struct{}

func (s avpPasswordt) Value(p *Packet, a AVP) interface{} {
	if p == nil {
		return ""
	}
	//Decode password. XOR against md5(p.server.secret+Authenticator)
	secAuth := append([]byte(nil), []byte(p.Secret)...)
	secAuth = append(secAuth, p.Authenticator[:]...)
	m := crypto.Hash(crypto.MD5).New()
	m.Write(secAuth)
	md := m.Sum(nil)
	pass := append([]byte(nil), a.Value...)
	if len(pass) == 16 {
		for i := 0; i < len(pass); i++ {
			pass[i] = pass[i] ^ md[i]
		}
		pass = bytes.TrimRight(pass, string([]rune{0}))
		return string(pass)
	}
	fmt.Println("[GetPassword] warning: not implemented for password > 16")
	return ""
}
func (s avpPasswordt) String(p *Packet, a AVP) string {
	return s.Value(p, a).(string)
}

type avpUint32EnumList []string

func (s avpUint32EnumList) Value(p *Packet, a AVP) interface{} {
	return uint32(binary.BigEndian.Uint32(a.Value))
}
func (s avpUint32EnumList) String(p *Packet, a AVP) string {
	number := int(binary.BigEndian.Uint32(a.Value))
	if number > len(s) {
		return "unknow " + strconv.Itoa(number)
	}
	out := s[number]
	if out == "" {
		return "unknow " + strconv.Itoa(number)
	}
	return out
}

type avpUint32Enum struct {
	t interface{} // t should from a uint32 type like AcctStatusTypeEnum
}

func (s avpUint32Enum) Value(p *Packet, a AVP) interface{} {
	value := reflect.New(reflect.TypeOf(s.t)).Elem()
	value.SetUint(uint64(binary.BigEndian.Uint32(a.Value)))
	return value.Interface()
}
func (s avpUint32Enum) String(p *Packet, a AVP) string {
	number := binary.BigEndian.Uint32(a.Value)
	value := reflect.New(reflect.TypeOf(s.t)).Elem()
	value.SetUint(uint64(number))
	method := value.MethodByName("String")
	if !method.IsValid() {
		return strconv.Itoa(int(number))
	}
	out := method.Call(nil)
	return out[0].Interface().(string)
}

type AcctStatusTypeEnum uint32

const (
	AcctStatusTypeEnumStart         AcctStatusTypeEnum = 1
	AcctStatusTypeEnumStop          AcctStatusTypeEnum = 2
	AcctStatusTypeEnumInterimUpdate AcctStatusTypeEnum = 3
	AcctStatusTypeEnumAccountingOn  AcctStatusTypeEnum = 7
	AcctStatusTypeEnumAccountingOff AcctStatusTypeEnum = 8
)

func (e AcctStatusTypeEnum) String() string {
	switch e {
	case AcctStatusTypeEnumStart:
		return "Start"
	case AcctStatusTypeEnumStop:
		return "Stop"
	case AcctStatusTypeEnumInterimUpdate:
		return "InterimUpdate"
	case AcctStatusTypeEnumAccountingOn:
		return "AccountingOn"
	case AcctStatusTypeEnumAccountingOff:
		return "AccountingOff"
	}
	return "unknow code " + strconv.Itoa(int(e))
}
