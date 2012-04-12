package radius
type AttributeDataType uint8
const (
	TEXT AttributeDataType= iota
	STRING AttributeDataType= iota
	ADDRESS AttributeDataType= iota
	VALUE AttributeDataType=  iota
	INTEGER AttributeDataType=  iota
	TIME AttributeDataType=  iota
)

const (
	UNLIMITED = -1
)
type Validation struct {
	Kind AttributeDataType
	MinLength int 
	MaxLength int //if < 0 unlimited 
	Decode func([]byte)([]byte,error)
}

func (v *Validation) Validate(){}


var validation  = map[AttributeType]Validation {
	UserName: {STRING,1,UNLIMITED,nil},
	UserPassword           :{STRING,16,128,nil},
	CHAPPassword           :{STRING,17,17,nil},
	NASIPAddress           : {ADDRESS,4,4,nil},
	NASPort : {VALUE,4,4,nil},
	ServiceType            :{},
	FramedProtocol         :{},
	FramedIPAddress        :{},
	FramedIPNetmask        :{},
	FramedRouting          :{},
	FilterId:{},
	FramedMTU              :{},
	FramedCompression      :{},
	LoginIPHost            :{},
	LoginService           :{},
	LoginTCPPort           :{},
	ReplyMessage           :{},
	CallbackNumber         :{},
	CallbackId             :{},
	FramedRoute            :{},
	FramedIPXNetwork       :{},
	State   :{},
	Class   :{},
	VendorSpecific         :{},
	SessionTimeout         :{},
	IdleTimeout            :{},
	TerminationAction      :{},
	CalledStationId        :{},
	CallingStationId       :{},
	NASIdentifier          :{},
	ProxyState             :{},
	LoginLATService        :{},
	LoginLATNode           :{},
	LoginLATGroup          :{},
	FramedAppleTalkLink    :{},
	FramedAppleTalkNetwork :{},
	FramedAppleTalkZone    :{},
	AcctStatusType         :{},
	AcctDelayTime          :{},
	AcctInputOctets        :{},
	AcctOutputOctets       :{},
	AcctSessionId          :{},
	AcctAuthentic          :{},
	AcctSessionTime        :{},
	AcctInputPackets       :{},
	AcctOutputPackets      :{},
	AcctTerminateCause     :{},
	AcctMultiSessionId     :{},
	AcctLinkCount          :{},

	CHAPChallenge :{},
	NASPortType   :{},
	PortLimit    :{},
	LoginLATPort  :{},
}


