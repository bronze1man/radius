package radius

import (
	"errors"
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

// enums:

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

// TODO finish it
const (
	AcctTerminateCauseEnumUserRequest AcctTerminateCauseEnum = 1
	AcctTerminateCauseEnumLostCarrier AcctTerminateCauseEnum = 2
	AcctTerminateCauseEnumLostService AcctTerminateCauseEnum = 3
	AcctTerminateCauseEnumIdleTimeout AcctTerminateCauseEnum = 4
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
	}
	return "unknow code " + strconv.Itoa(int(e))
}
