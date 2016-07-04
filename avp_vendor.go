package radius

import (
	"encoding/binary"
	"fmt"
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

	return fmt.Sprintf("{Vendor: %d, Attr: %d, Value: %#v}", vsa.Vendor, vsa.Type, vsa.Value)
}

// encode VSA attribute under Vendor-Specific AVP
func (vsa VSA) ToAVP() AVP {
	vsa_len := len(vsa.Value)
	// vendor id (4) + attr type (1) + attr len (1)
	// TODO - for WiMAX vendor there is extra byte in VSA header
	vsa_value := make([]byte, vsa_len+6)
	binary.BigEndian.PutUint32(vsa_value[0:4], vsa.Vendor)
	vsa_value[4] = uint8(vsa.Type)
	vsa_value[5] = uint8(vsa_len + 2)
	copy(vsa_value[6:], vsa.Value)

	avp := AVP{Type: VendorSpecific, Value: vsa_value}

	return avp
}
