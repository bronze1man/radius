package radius

import (
    "bytes"
    "crypto"
)

var avpPassword avpPasswordt

type avpPasswordt struct{}

func (s avpPasswordt) Value(p *Packet, a AVP) interface{} {
        if p == nil {
                return ""
        }

        b := a.Value
        password := make([]byte, len(b))
        last := make([]byte, 16)
        copy(last, p.Authenticator[:])
        hash := crypto.Hash(crypto.MD5).New()
        blocks := 0

        for len(b) > 0 {
            hash.Write( append([]byte(p.Secret), last...))
            digest := hash.Sum(nil)
            hash.Reset()

            // see crypto/cipher/xor.go for faster implementation
            for i := 0; i < 16; i++ {
                password[16 * blocks + i] = b[i]^digest[i]
            }
            // next block
            last = b[:16]
            b = b[16:]
            blocks += 1
        }

        //remove padding zeroes
        password = bytes.TrimRight(password, string([]byte{0}))
        return string(password)
}

func (s avpPasswordt) String(p *Packet, a AVP) string {
        return s.Value(p, a).(string)
}

