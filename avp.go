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

func (a AVP) Copy() AVP {
	value := make([]byte, len(a.Value))
	copy(value, a.Value)
	return AVP{
		Type:  a.Type,
		Value: a.Value,
	}
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

	buff := a.Value
	pass := make([]byte, 0)
	last := make([]byte, 16)
	copy(last, p.Authenticator[:])

	for len(buff) > 0 {
		m := crypto.Hash(crypto.MD5).New()
		m.Write(append([]byte(p.Secret), last...))
		h := m.Sum(nil)
		for i := 0; i < 16; i++ {
			pass = append(pass, buff[i]^h[i])
		}
		last = buff[:16]
		buff = buff[16:]
	}

	pass = bytes.TrimRight(pass, string([]rune{0}))
	return string(pass)
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

var avpEapMessage avpEapMessaget

type avpEapMessaget struct{}

func (s avpEapMessaget) Value(p *Packet, a AVP) interface{} {
	eap, err := EapDecode(a.Value)
	if err != nil {
		//TODO error handle
		fmt.Println("EapDecode fail ", err)
		return nil
	}
	return eap

}
func (s avpEapMessaget) String(p *Packet, a AVP) string {
	eap := s.Value(p, a)
	if eap == nil {
		return "nil"
	}
	return eap.(*EapPacket).String()
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

type NASPortTypeEnum uint32

// TODO finish it
const (
	NASPortTypeEnumAsync            NASPortTypeEnum = 0
	NASPortTypeEnumSync             NASPortTypeEnum = 1
	NASPortTypeEnumISDNSync         NASPortTypeEnum = 2
	NASPortTypeEnumISDNSyncV120     NASPortTypeEnum = 3
	NASPortTypeEnumISDNSyncV110     NASPortTypeEnum = 4
	NASPortTypeEnumVirtual          NASPortTypeEnum = 5
	NASPortTypeEnumPIAFS            NASPortTypeEnum = 6
	NASPortTypeEnumHDLCClearChannel NASPortTypeEnum = 7
	NASPortTypeEnumEthernet         NASPortTypeEnum = 15
	NASPortTypeEnumCable            NASPortTypeEnum = 17
)

func (e NASPortTypeEnum) String() string {
	switch e {
	case NASPortTypeEnumAsync:
		return "Async"
	case NASPortTypeEnumSync:
		return "Sync"
	case NASPortTypeEnumISDNSync:
		return "ISDNSync"
	case NASPortTypeEnumISDNSyncV120:
		return "ISDNSyncV120"
	case NASPortTypeEnumISDNSyncV110:
		return "ISDNSyncV110"
	case NASPortTypeEnumVirtual:
		return "Virtual"
	case NASPortTypeEnumPIAFS:
		return "PIAFS"
	case NASPortTypeEnumHDLCClearChannel:
		return "HDLCClearChannel"
	case NASPortTypeEnumEthernet:
		return "Ethernet"
	case NASPortTypeEnumCable:
		return "Cable"
	}
	return "unknow code " + strconv.Itoa(int(e))
}

type ServiceTypeEnum uint32

// TODO finish it
const (
	ServiceTypeEnumLogin          ServiceTypeEnum = 1
	ServiceTypeEnumFramed         ServiceTypeEnum = 2
	ServiceTypeEnumCallbackLogin  ServiceTypeEnum = 3
	ServiceTypeEnumCallbackFramed ServiceTypeEnum = 4
	ServiceTypeEnumOutbound       ServiceTypeEnum = 5
)

func (e ServiceTypeEnum) String() string {
	switch e {
	case ServiceTypeEnumLogin:
		return "Login"
	case ServiceTypeEnumFramed:
		return "Framed"
	case ServiceTypeEnumCallbackLogin:
		return "CallbackLogin"
	case ServiceTypeEnumCallbackFramed:
		return "CallbackFramed"
	case ServiceTypeEnumOutbound:
		return "Outbound"
	}
	return "unknow code " + strconv.Itoa(int(e))
}

type AcctTerminateCauseEnum uint32

const (
	AcctTerminateCauseEnumUserRequest        AcctTerminateCauseEnum = 1
	AcctTerminateCauseEnumLostCarrier        AcctTerminateCauseEnum = 2
	AcctTerminateCauseEnumLostService        AcctTerminateCauseEnum = 3
	AcctTerminateCauseEnumIdleTimeout        AcctTerminateCauseEnum = 4
	AcctTerminateCauseEnumSessionTimout      AcctTerminateCauseEnum = 5
	AcctTerminateCauseEnumAdminReset         AcctTerminateCauseEnum = 6
	AcctTerminateCauseEnumAdminReboot        AcctTerminateCauseEnum = 7
	AcctTerminateCauseEnumPortError          AcctTerminateCauseEnum = 8
	AcctTerminateCauseEnumNASError           AcctTerminateCauseEnum = 9
	AcctTerminateCauseEnumNASRequest         AcctTerminateCauseEnum = 10
	AcctTerminateCauseEnumNASReboot          AcctTerminateCauseEnum = 11
	AcctTerminateCauseEnumPortUnneeded       AcctTerminateCauseEnum = 12
	AcctTerminateCauseEnumPortPreempted      AcctTerminateCauseEnum = 13
	AcctTerminateCauseEnumPortSuspended      AcctTerminateCauseEnum = 14
	AcctTerminateCauseEnumServiceUnavailable AcctTerminateCauseEnum = 15
	AcctTerminateCauseEnumCallbkack          AcctTerminateCauseEnum = 16
	AcctTerminateCauseEnumUserError          AcctTerminateCauseEnum = 17
	AcctTerminateCauseEnumHostRequest        AcctTerminateCauseEnum = 18
)

func (e AcctTerminateCauseEnum) String() string {
	switch e {
	case AcctTerminateCauseEnumUserRequest:
		return "UserRequest"
	case AcctTerminateCauseEnumLostCarrier:
		return "LostCarrier"
	case AcctTerminateCauseEnumLostService:
		return "LostService"
	case AcctTerminateCauseEnumIdleTimeout:
		return "IdleTimeout"
	case AcctTerminateCauseEnumSessionTimout:
		return "SessionTimeout"
	case AcctTerminateCauseEnumAdminReset:
		return "AdminReset"
	case AcctTerminateCauseEnumAdminReboot:
		return "AdminReboot"
	case AcctTerminateCauseEnumPortError:
		return "PortError"
	case AcctTerminateCauseEnumNASError:
		return "NASError"
	case AcctTerminateCauseEnumNASRequest:
		return "NASRequest"
	case AcctTerminateCauseEnumNASReboot:
		return "NASReboot"
	case AcctTerminateCauseEnumPortUnneeded:
		return "PortUnneeded"
	case AcctTerminateCauseEnumPortPreempted:
		return "PortPreempted"
	case AcctTerminateCauseEnumPortSuspended:
		return "PortSuspended"
	case AcctTerminateCauseEnumServiceUnavailable:
		return "ServiceUnavailable"
	case AcctTerminateCauseEnumCallbkack:
		return "Callback"
	case AcctTerminateCauseEnumUserError:
		return "UserError"
	case AcctTerminateCauseEnumHostRequest:
		return "HostRequest"
	}
	return "unknow code " + strconv.Itoa(int(e))
}
