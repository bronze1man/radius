package radius

import (
    "fmt"
)

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

