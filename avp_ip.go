package radius

import (
    "net"
)

var avpIP avpIPt

type avpIPt struct{}

func (s avpIPt) Value(p *Packet, a AVP) interface{} {
        return net.IP(a.Value)
}
func (s avpIPt) String(p *Packet, a AVP) string {
        return net.IP(a.Value).String()
}

