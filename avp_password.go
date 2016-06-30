package radius

import (
    "bytes"
    "crypto"
    "fmt"
)

var avpPassword avpPasswordt

type avpPasswordt struct{}

func (s avpPasswordt) Value(p *Packet, a AVP) interface{} {
        if p == nil {
                return ""
        }
        //Decode password. XOR against md5(p.server.secret+Authenticator)
        secAuth := append([]byte(nil), []byte(p.Secret)...)
        secAuth = append(secAuth, p.Authenticator[:]...)
        m := crypto.Hash(crypto.MD5).New()
        m.Write(secAuth)
        md := m.Sum(nil)
        pass := append([]byte(nil), a.Value...)
        if len(pass) == 16 {
                for i := 0; i < len(pass); i++ {
                        pass[i] = pass[i] ^ md[i]
                }
                pass = bytes.TrimRight(pass, string([]rune{0}))
                return string(pass)
        }
        fmt.Println("[GetPassword] warning: not implemented for password > 16")
        return ""
}

func (s avpPasswordt) String(p *Packet, a AVP) string {
        return s.Value(p, a).(string)
}

