package radius

var avpString avpStringt

type avpStringt struct{}

func (s avpStringt) Value(p *Packet, a AVP) interface{} {
        return string(a.Value)
}
func (s avpStringt) String(p *Packet, a AVP) string {
        return string(a.Value)
}


