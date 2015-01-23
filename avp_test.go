package radius

import (
	"testing"
)

func TestAvpUint32Enum(ot *testing.T) {
	enum:=avpUint32Enum{AcctStatusTypeEnum(0)}
	s:=enum.String(nil,AVP{
			Value: []byte{0,0,0,1},
		})
	ok(s=="Start")
	s1:=enum.Value(nil,AVP{
			Value: []byte{0,0,0,1},
		}).(AcctStatusTypeEnum)
	ok(s1==AcctStatusTypeEnumStart)
}