package radius

import (
	"encoding/binary"
	"fmt"
	"strconv"
)

type EapCode uint8

const (
	EapCodeRequest  EapCode = 1
	EapCodeResponse EapCode = 2
	EapCodeSuccess  EapCode = 3
	EapCodeFailure  EapCode = 4
)

func (c EapCode) String() string {
	switch c {
	case EapCodeRequest:
		return "Request"
	case EapCodeResponse:
		return "Response"
	case EapCodeSuccess:
		return "Success"
	case EapCodeFailure:
		return "Failure"
	default:
		return "unknow EapCode " + strconv.Itoa(int(c))
	}
}

type EapType uint8

const (
	EapTypeIdentity         EapType = 1
	EapTypeNotification     EapType = 2
	EapTypeNak              EapType = 3 //Response only
	EapTypeMd5Challenge     EapType = 4
	EapTypeOneTimePassword  EapType = 5 //otp
	EapTypeGenericTokenCard EapType = 6 //gtc
	EapTypeMSCHAPV2         EapType = 26
	EapTypeExpandedTypes    EapType = 254
	EapTypeExperimentalUse  EapType = 255
)

func (c EapType) String() string {
	switch c {
	case EapTypeIdentity:
		return "Identity"
	case EapTypeNotification:
		return "Notification"
	case EapTypeNak:
		return "Nak"
	case EapTypeMd5Challenge:
		return "Md5Challenge"
	case EapTypeOneTimePassword:
		return "OneTimePassword"
	case EapTypeGenericTokenCard:
		return "GenericTokenCard"
	case EapTypeMSCHAPV2:
		return "MSCHAPV2"
	case EapTypeExpandedTypes:
		return "ExpandedTypes"
	case EapTypeExperimentalUse:
		return "ExperimentalUse"
	default:
		return "unknow EapType " + strconv.Itoa(int(c))
	}
}

type EapPacket struct {
	Code       EapCode
	Identifier uint8
	Type       EapType
	Data       []byte
}

func (a *EapPacket) String() string {
	return fmt.Sprintf("Eap Code:%s id:%d Type:%s Data:[%s]", a.Code.String(), a.Identifier, a.Type.String(), a.valueString())
}

func (a *EapPacket) valueString() string {
	switch a.Type {
	case EapTypeIdentity:
		return fmt.Sprintf("%#v", string(a.Data)) //应该是字符串,但是也有可能被搞错
	case EapTypeMSCHAPV2:
		mcv, err := MsChapV2PacketFromEap(a)
		if err != nil {
			return err.Error()
		}
		return mcv.String()
	}
	return fmt.Sprintf("%#v", a.Data)
}

func (a *EapPacket) Copy() *EapPacket {
	eap := *a
	eap.Data = append([]byte(nil), a.Data...)
	return &eap
}

func (a *EapPacket) Encode() (b []byte) {
	b = make([]byte, len(a.Data)+5)
	b[0] = byte(a.Code)
	b[1] = byte(a.Identifier)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(a.Data)+5))
	b[4] = byte(a.Type)
	copy(b[5:], a.Data)
	return b
}

func (a *EapPacket) ToEAPMessage() *AVP {
	return &AVP{
		Type:  EAPMessage,
		Value: a.Encode(),
	}
}

func EapDecode(b []byte) (eap *EapPacket, err error) {
	if len(b) < 5 {
		return nil, fmt.Errorf("[EapDecode] protocol error input too small 1")
	}
	length := binary.BigEndian.Uint16(b[2:4])
	if len(b) < int(length) {
		return nil, fmt.Errorf("[EapDecode] protocol error input too small 2")
	}
	eap = &EapPacket{
		Code:       EapCode(b[0]),
		Identifier: uint8(b[1]),
		Type:       EapType(b[4]),
		Data:       b[5:length],
	}
	return eap, nil
}
