package radius

import (
	//"bytes"
	"encoding/binary"
	//"errors"
	"fmt"
	//"net"
	//"reflect"
	//"strconv"
)

// Vendor
type VSA struct {
	Vendor uint32
	Type   uint8
	Value  []byte
}

var avpVendor avpVendort

type avpVendort struct{}

func (s avpVendort) Value(p *Packet, a AVP) interface{} {
	// as-is
	return a.Value
}

func (s avpVendort) String(p *Packet, a AVP) string {
	vsa := new(VSA)
	value := a.Value
	vsa.Vendor = binary.BigEndian.Uint32(value[0:4])
	vsa.Type = uint8(value[4])
	vsa.Value = make([]byte, value[5]-2)
	copy(vsa.Value, value[6:])

	return fmt.Sprintf("{Vendor: %d, Type: %d, Value: %#v}", vsa.Vendor, vsa.Type, vsa.Value)
}
