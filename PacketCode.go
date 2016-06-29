package radius

import (
	"strconv"
)

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
	DisconnectRequest  PacketCode = 40
	DisconnectAccept   PacketCode = 41
	DisconnectReject   PacketCode = 42
	CoARequest         PacketCode = 43
	CoAAccept          PacketCode = 44
	CoaReject          PacketCode = 45
	Reserved           PacketCode = 255
)

var packetCodeName = map[PacketCode]string{
	AccessRequest:      "AccessRequest",
	AccessAccept:       "AccessAccept",
	AccessReject:       "AccessReject",
	AccountingRequest:  "AccountingRequest",
	AccountingResponse: "AccountingResponse",
	AccessChallenge:    "AccessChallenge",
	StatusServer:       "StatusServer",
	StatusClient:       "StatusClient",
	DisconnectRequest:  "DisconnectRequest",
	DisconnectAccept:   "DisconnectAccept",
	DisconnectReject:   "DisconnectReject",
	CoARequest:         "CoARequest",
	CoAAccept:          "CoAAccept",
	CoaReject:          "CoaReject",
	Reserved:           "Reserved",
}

func (p PacketCode) String() string {
	name, ok := packetCodeName[p]
	if ok {
		return name
	}

	return "unknown packet code " + strconv.Itoa(int(p))
}
