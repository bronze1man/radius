package radius

import (
        "encoding/binary"
        "strconv"
)

// not used?
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

