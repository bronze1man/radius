package radius

import (
    "fmt"
)

var avpBinary avpBinaryt

type avpBinaryt struct{}

func (s avpBinaryt) Value(p *Packet, a AVP) interface{} {
        return a.Value
}
func (s avpBinaryt) String(p *Packet, a AVP) string {
        return fmt.Sprintf("%#v", a.Value)
}

