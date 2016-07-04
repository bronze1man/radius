package radius

import (
	"strconv"
)

type AttributeType uint8

const (
	//start rfc2865
	_                                    = iota //drop the zero
	UserName               AttributeType = iota //1
	UserPassword           AttributeType = iota //2
	CHAPPassword           AttributeType = iota //3
	NASIPAddress           AttributeType = iota //4
	NASPort                AttributeType = iota //5
	ServiceType            AttributeType = iota //6
	FramedProtocol         AttributeType = iota //7
	FramedIPAddress        AttributeType = iota //8
	FramedIPNetmask        AttributeType = iota //9
	FramedRouting          AttributeType = iota //10
	FilterId               AttributeType = iota //11
	FramedMTU              AttributeType = iota //12
	FramedCompression      AttributeType = iota //13
	LoginIPHost            AttributeType = iota //14
	LoginService           AttributeType = iota //15
	LoginTCPPort           AttributeType = iota //16
	_                                    = iota //17 unassigned
	ReplyMessage           AttributeType = iota //18
	CallbackNumber         AttributeType = iota //19
	CallbackId             AttributeType = iota //20
	_                                    = iota //21 unassigned
	FramedRoute            AttributeType = iota //22
	FramedIPXNetwork       AttributeType = iota //23
	State                  AttributeType = iota //24
	Class                  AttributeType = iota //25
	VendorSpecific         AttributeType = iota
	SessionTimeout         AttributeType = iota
	IdleTimeout            AttributeType = iota
	TerminationAction      AttributeType = iota
	CalledStationId        AttributeType = iota
	CallingStationId       AttributeType = iota
	NASIdentifier          AttributeType = iota
	ProxyState             AttributeType = iota
	LoginLATService        AttributeType = iota
	LoginLATNode           AttributeType = iota
	LoginLATGroup          AttributeType = iota
	FramedAppleTalkLink    AttributeType = iota
	FramedAppleTalkNetwork AttributeType = iota
	FramedAppleTalkZone    AttributeType = iota
	AcctStatusType         AttributeType = iota
	AcctDelayTime          AttributeType = iota
	AcctInputOctets        AttributeType = iota
	AcctOutputOctets       AttributeType = iota
	AcctSessionId          AttributeType = iota
	AcctAuthentic          AttributeType = iota
	AcctSessionTime        AttributeType = iota
	AcctInputPackets       AttributeType = iota
	AcctOutputPackets      AttributeType = iota
	AcctTerminateCause     AttributeType = iota
	AcctMultiSessionId     AttributeType = iota
	AcctLinkCount          AttributeType = iota
	AcctInputGigawords     AttributeType = iota //52
	AcctOutputGigawords    AttributeType = iota
	Unassigned1            AttributeType = iota
	EventTimestamp         AttributeType = iota
	EgressVLANID           AttributeType = iota
	IngressFilters         AttributeType = iota
	EgressVLANName         AttributeType = iota
	UserPriorityTable      AttributeType = iota //59
	CHAPChallenge          AttributeType = 60
	NASPortType            AttributeType = 61
	PortLimit              AttributeType = 62
	LoginLATPort           AttributeType = 63
	//end rfc2865 rfc 2866
	TunnelType                   AttributeType = iota
	TunnelMediumType             AttributeType = iota
	TunnelClientEndpoint         AttributeType = iota
	TunnelServerEndpoint         AttributeType = iota
	AcctTunnelConnection         AttributeType = iota
	TunnelPassword               AttributeType = iota
	ARAPPassword                 AttributeType = iota
	ARAPFeatures                 AttributeType = iota
	ARAPZoneAccess               AttributeType = iota
	ARAPSecurity                 AttributeType = iota
	ARAPSecurityData             AttributeType = iota
	PasswordRetry                AttributeType = iota
	Prompt                       AttributeType = iota
	ConnectInfo                  AttributeType = iota
	ConfigurationToken           AttributeType = iota
	EAPMessage                   AttributeType = iota
	MessageAuthenticator         AttributeType = iota
	TunnelPrivateGroupID         AttributeType = iota
	TunnelAssignmentID           AttributeType = iota
	TunnelPreference             AttributeType = iota
	ARAPChallengeResponse        AttributeType = iota
	AcctInterimInterval          AttributeType = iota
	AcctTunnelPacketsLost        AttributeType = iota
	NASPortId                    AttributeType = iota
	FramedPool                   AttributeType = iota
	CUI                          AttributeType = iota
	TunnelClientAuthID           AttributeType = iota
	TunnelServerAuthID           AttributeType = iota
	NASFilterRule                AttributeType = iota
	Unassigned                   AttributeType = iota
	OriginatingLineInfo          AttributeType = iota
	NASIPv6Address               AttributeType = iota
	FramedInterfaceId            AttributeType = iota
	FramedIPv6Prefix             AttributeType = iota
	LoginIPv6Host                AttributeType = iota
	FramedIPv6Route              AttributeType = iota
	FramedIPv6Pool               AttributeType = iota
	ErrorCause                   AttributeType = iota
	EAPKeyName                   AttributeType = iota
	DigestResponse               AttributeType = iota
	DigestRealm                  AttributeType = iota
	DigestNonce                  AttributeType = iota
	DigestResponseAuth           AttributeType = iota
	DigestNextnonce              AttributeType = iota
	DigestMethod                 AttributeType = iota
	DigestURI                    AttributeType = iota
	DigestQop                    AttributeType = iota
	DigestAlgorithm              AttributeType = iota
	DigestEntityBodyHash         AttributeType = iota
	DigestCNonce                 AttributeType = iota
	DigestNonceCount             AttributeType = iota
	DigestUsername               AttributeType = iota
	DigestOpaque                 AttributeType = iota
	DigestAuthParam              AttributeType = iota
	DigestAKAAuts                AttributeType = iota
	DigestDomain                 AttributeType = iota
	DigestStale                  AttributeType = iota
	DigestHA1                    AttributeType = iota
	SIPAOR                       AttributeType = iota
	DelegatedIPv6Prefix          AttributeType = iota
	MIP6FeatureVector            AttributeType = iota
	MIP6HomeLinkPrefix           AttributeType = iota
	OperatorName                 AttributeType = iota
	LocationInformation          AttributeType = iota
	LocationData                 AttributeType = iota
	BasicLocationPolicyRules     AttributeType = iota
	ExtendedLocationPolicyRules  AttributeType = iota
	LocationCapable              AttributeType = iota
	RequestedLocationInfo        AttributeType = iota
	FramedManagementProtocol     AttributeType = iota
	ManagementTransportProtectio AttributeType = iota
	ManagementPolicyId           AttributeType = iota
	ManagementPrivilegeLevel     AttributeType = iota
	PKMSSCert                    AttributeType = iota
	PKMCACert                    AttributeType = iota
	PKMConfigSettings            AttributeType = iota
	PKMCryptosuiteList           AttributeType = iota
	PKMSAID                      AttributeType = iota
	PKMSADescriptor              AttributeType = iota
	PKMAuthKey                   AttributeType = iota
	DSLiteTunnelName             AttributeType = iota
	MobileNodeIdentifier         AttributeType = iota
	ServiceSelection             AttributeType = iota
	PMIP6HomeLMAIPv6Address      AttributeType = iota
	PMIP6VisitedLMAIPv6Address   AttributeType = iota
	PMIP6HomeLMAIPv4Address      AttributeType = iota
	PMIP6VisitedLMAIPv4Address   AttributeType = iota
	PMIP6HomeHNPrefix            AttributeType = iota
	PMIP6VisitedHNPrefix         AttributeType = iota
	PMIP6HomeInterfaceID         AttributeType = iota
	PMIP6VisitedInterfaceID      AttributeType = iota
	PMIP6HomeIPv4HoA             AttributeType = iota
	PMIP6VisitedIPv4HoA          AttributeType = iota
	PMIP6HomeDHCP4ServerAddress  AttributeType = iota
	PMIP6VisitedDHCP4ServerAddre AttributeType = iota
	PMIP6HomeDHCP6ServerAddress  AttributeType = iota
	PMIP6VisitedDHCP6ServerAddre AttributeType = iota
	UnassignedStart              AttributeType = 161
	UnassignedEnd                AttributeType = 191

	ExperimentalStart           AttributeType = 192
	ExperimentalEnd             AttributeType = 223
	ImplementationSpecificStart AttributeType = 224
	ImplementationSpecificEnd   AttributeType = 240
	ReservedStart               AttributeType = 241
	ReservedEnd                 AttributeType = 254
)

func getAttributeTypeDesc(t AttributeType) attributeTypeDesc {
	desc := attributeTypeMap[int(t)]
	if desc.dataType == nil {
		desc.dataType = avpBinary
	}
	if desc.name == "" {
		desc.name = "Unknow " + strconv.Itoa(int(t))
	}
	return desc
}

type attributeTypeDesc struct {
	name     string
	dataType avpDataType
}

var attributeTypeMap = [256]attributeTypeDesc{
	0:                      {"Unassigned 0", avpBinary},
	UserName:               {"UserName", avpString},
	UserPassword:           {"UserPassword", avpPassword},
	CHAPPassword:           {"CHAPPassword", avpBinary},
	NASIPAddress:           {"NASIPAddress", avpIP},
	NASPort:                {"NASPort", avpUint32},
	ServiceType:            {"ServiceType", avpUint32Enum{ServiceTypeEnum(0)}},
	FramedProtocol:         {"FramedProtocol", avpUint32},
	FramedIPAddress:        {"FramedIPAddress", avpIP},
	FramedIPNetmask:        {"FramedIPNetmask", avpIP},
	FramedRouting:          {"FramedRouting", avpUint32},
	FilterId:               {"FilterId", avpString},
	FramedMTU:              {"FramedMTU", avpUint32},
	FramedCompression:      {"FramedCompression", avpUint32},
	LoginIPHost:            {"LoginIPHost", avpIP},
	LoginService:           {"LoginService", avpUint32},
	LoginTCPPort:           {"LoginTCPPort", avpUint32},
	17:                     {"Unassigned 17", avpBinary},
	ReplyMessage:           {"ReplyMessage", avpString},
	CallbackNumber:         {"CallbackNumber", avpString},
	CallbackId:             {"CallbackId", avpString},
	21:                     {"Unassigned 21", avpBinary},
	FramedRoute:            {"FramedRoute", avpString},
	FramedIPXNetwork:       {"FramedIPXNetwork", avpIP},
	State:                  {"State", avpString},
	Class:                  {"Class", avpString},
	VendorSpecific:         {"VendorSpecific", avpVendor},
	SessionTimeout:         {"SessionTimeout", avpUint32},
	IdleTimeout:            {"IdleTimeout", avpUint32},
	TerminationAction:      {"TerminationAction", avpUint32},
	CalledStationId:        {"CalledStationId", avpString},
	CallingStationId:       {"CallingStationId", avpString},
	NASIdentifier:          {"NASIdentifier", avpString},
	ProxyState:             {"ProxyState", avpString},
	LoginLATService:        {"LoginLATService", avpString},
	LoginLATNode:           {"LoginLATNode", avpString},
	LoginLATGroup:          {"LoginLATGroup", avpString},
	FramedAppleTalkLink:    {"FramedAppleTalkLink", avpUint32},
	FramedAppleTalkNetwork: {"FramedAppleTalkNetwork", avpUint32},
	FramedAppleTalkZone:    {"FramedAppleTalkZone", avpUint32},
	AcctStatusType:         {"AcctStatusType", avpUint32Enum{AcctStatusTypeEnum(0)}},
	AcctDelayTime:          {"AcctDelayTime", avpUint32},
	AcctInputOctets:        {"AcctInputOctets", avpUint32},
	AcctOutputOctets:       {"AcctOutputOctets", avpUint32},
	AcctSessionId:          {"AcctSessionId", avpString},
	AcctAuthentic:          {"AcctAuthentic", avpUint32},
	AcctSessionTime:        {"AcctSessionTime", avpUint32},
	AcctInputPackets:       {"AcctInputPackets", avpUint32},
	AcctOutputPackets:      {"AcctOutputPackets", avpUint32},
	AcctTerminateCause:     {"AcctTerminateCause", avpUint32Enum{AcctTerminateCauseEnum(0)}},
	AcctMultiSessionId:     {"AcctMultiSessionId", avpString},
	AcctLinkCount:          {"AcctLinkCount", avpUint32},
	AcctInputGigawords:     {"AcctInputGigawords", avpUint32},
	AcctOutputGigawords:    {"AcctOutputGigawords", avpUint32},
	Unassigned1:            {"Unassigned1", avpBinary},
	EventTimestamp:         {"EventTimestamp", avpBinary},
	EgressVLANID:           {"EgressVLANID", avpBinary},
	IngressFilters:         {"IngressFilters", avpBinary},
	EgressVLANName:         {"EgressVLANName", avpBinary},
	UserPriorityTable:      {"UserPriorityTable", avpBinary},
	CHAPChallenge:          {"CHAPChallenge", avpBinary},
	NASPortType:            {"NASPortType", avpUint32Enum{NASPortTypeEnum(0)}},
	PortLimit:              {"PortLimit", avpBinary},
	LoginLATPort:           {"LoginLATPort", avpBinary},
	//end rfc2865://end rfc2865
	TunnelType:                   {"TunnelType", avpBinary},
	TunnelMediumType:             {"TunnelMediumType", avpBinary},
	TunnelClientEndpoint:         {"TunnelClientEndpoint", avpBinary},
	TunnelServerEndpoint:         {"TunnelServerEndpoint", avpBinary},
	AcctTunnelConnection:         {"AcctTunnelConnection", avpBinary},
	TunnelPassword:               {"TunnelPassword", avpBinary},
	ARAPPassword:                 {"ARAPPassword", avpBinary},
	ARAPFeatures:                 {"ARAPFeatures", avpBinary},
	ARAPZoneAccess:               {"ARAPZoneAccess", avpBinary},
	ARAPSecurity:                 {"ARAPSecurity", avpBinary},
	ARAPSecurityData:             {"ARAPSecurityData", avpBinary},
	PasswordRetry:                {"PasswordRetry", avpBinary},
	Prompt:                       {"Prompt", avpBinary},
	ConnectInfo:                  {"ConnectInfo", avpBinary},
	ConfigurationToken:           {"ConfigurationToken", avpString},
	EAPMessage:                   {"EAPMessage", avpEapMessage},
	MessageAuthenticator:         {"MessageAuthenticator", avpBinary},
	TunnelPrivateGroupID:         {"TunnelPrivateGroupID", avpBinary},
	TunnelAssignmentID:           {"TunnelAssignmentID", avpBinary},
	TunnelPreference:             {"TunnelPreference", avpBinary},
	ARAPChallengeResponse:        {"ARAPChallengeResponse", avpBinary},
	AcctInterimInterval:          {"AcctInterimInterval", avpBinary},
	AcctTunnelPacketsLost:        {"AcctTunnelPacketsLost", avpBinary},
	NASPortId:                    {"NASPortId", avpString},
	FramedPool:                   {"FramedPool", avpBinary},
	CUI:                          {"CUI", avpBinary},
	TunnelClientAuthID:           {"TunnelClientAuthID", avpBinary},
	TunnelServerAuthID:           {"TunnelServerAuthID", avpBinary},
	NASFilterRule:                {"NASFilterRule", avpBinary},
	Unassigned:                   {"Unassigned", avpBinary},
	OriginatingLineInfo:          {"OriginatingLineInfo", avpBinary},
	NASIPv6Address:               {"NASIPv6Address", avpBinary},
	FramedInterfaceId:            {"FramedInterfaceId", avpBinary},
	FramedIPv6Prefix:             {"FramedIPv6Prefix", avpBinary},
	LoginIPv6Host:                {"LoginIPv6Host", avpBinary},
	FramedIPv6Route:              {"FramedIPv6Route", avpBinary},
	FramedIPv6Pool:               {"FramedIPv6Pool", avpBinary},
	ErrorCause:                   {"ErrorCause", avpBinary},
	EAPKeyName:                   {"EAPKeyName", avpBinary},
	DigestResponse:               {"DigestResponse", avpBinary},
	DigestRealm:                  {"DigestRealm", avpBinary},
	DigestNonce:                  {"DigestNonce", avpBinary},
	DigestResponseAuth:           {"DigestResponseAuth", avpBinary},
	DigestNextnonce:              {"DigestNextnonce", avpBinary},
	DigestMethod:                 {"DigestMethod", avpBinary},
	DigestURI:                    {"DigestURI", avpBinary},
	DigestQop:                    {"DigestQop", avpBinary},
	DigestAlgorithm:              {"DigestAlgorithm", avpBinary},
	DigestEntityBodyHash:         {"DigestEntityBodyHash", avpBinary},
	DigestCNonce:                 {"DigestCNonce", avpBinary},
	DigestNonceCount:             {"DigestNonceCount", avpBinary},
	DigestUsername:               {"DigestUsername", avpBinary},
	DigestOpaque:                 {"DigestOpaque", avpBinary},
	DigestAuthParam:              {"DigestAuthParam", avpBinary},
	DigestAKAAuts:                {"DigestAKAAuts", avpBinary},
	DigestDomain:                 {"DigestDomain", avpBinary},
	DigestStale:                  {"DigestStale", avpBinary},
	DigestHA1:                    {"DigestHA1", avpBinary},
	SIPAOR:                       {"SIPAOR", avpBinary},
	DelegatedIPv6Prefix:          {"DelegatedIPv6Prefix", avpBinary},
	MIP6FeatureVector:            {"MIP6FeatureVector", avpBinary},
	MIP6HomeLinkPrefix:           {"MIP6HomeLinkPrefix", avpBinary},
	OperatorName:                 {"OperatorName", avpBinary},
	LocationInformation:          {"LocationInformation", avpBinary},
	LocationData:                 {"LocationData", avpBinary},
	BasicLocationPolicyRules:     {"BasicLocationPolicyRules", avpBinary},
	ExtendedLocationPolicyRules:  {"ExtendedLocationPolicyRules", avpBinary},
	LocationCapable:              {"LocationCapable", avpBinary},
	RequestedLocationInfo:        {"RequestedLocationInfo", avpBinary},
	FramedManagementProtocol:     {"FramedManagementProtocol", avpBinary},
	ManagementTransportProtectio: {"ManagementTransportProtection", avpBinary},
	ManagementPolicyId:           {"ManagementPolicyId", avpBinary},
	ManagementPrivilegeLevel:     {"ManagementPrivilegeLevel", avpBinary},
	PKMSSCert:                    {"PKMSSCert", avpBinary},
	PKMCACert:                    {"PKMCACert", avpBinary},
	PKMConfigSettings:            {"PKMConfigSettings", avpBinary},
	PKMCryptosuiteList:           {"PKMCryptosuiteList", avpBinary},
	PKMSAID:                      {"PKMSAID", avpBinary},
	PKMSADescriptor:              {"PKMSADescriptor", avpBinary},
	PKMAuthKey:                   {"PKMAuthKey", avpBinary},
	DSLiteTunnelName:             {"DSLiteTunnelName", avpBinary},
	MobileNodeIdentifier:         {"MobileNodeIdentifier", avpBinary},
	ServiceSelection:             {"ServiceSelection", avpBinary},
	PMIP6HomeLMAIPv6Address:      {"PMIP6HomeLMAIPv6Address", avpBinary},
	PMIP6VisitedLMAIPv6Address:   {"PMIP6VisitedLMAIPv6Address", avpBinary},
	PMIP6HomeLMAIPv4Address:      {"PMIP6HomeLMAIPv4Address", avpBinary},
	PMIP6VisitedLMAIPv4Address:   {"PMIP6VisitedLMAIPv4Address", avpBinary},
	PMIP6HomeHNPrefix:            {"PMIP6HomeHNPrefix", avpBinary},
	PMIP6VisitedHNPrefix:         {"PMIP6VisitedHNPrefix", avpBinary},
	PMIP6HomeInterfaceID:         {"PMIP6HomeInterfaceID", avpBinary},
	PMIP6VisitedInterfaceID:      {"PMIP6VisitedInterfaceID", avpBinary},
	PMIP6HomeIPv4HoA:             {"PMIP6HomeIPv4HoA", avpBinary},
	PMIP6VisitedIPv4HoA:          {"PMIP6VisitedIPv4HoA", avpBinary},
	PMIP6HomeDHCP4ServerAddress:  {"PMIP6HomeDHCP4ServerAddress", avpBinary},
	PMIP6VisitedDHCP4ServerAddre: {"PMIP6VisitedDHCP4ServerAddress", avpBinary},
	PMIP6HomeDHCP6ServerAddress:  {"PMIP6HomeDHCP6ServerAddress", avpBinary},
	PMIP6VisitedDHCP6ServerAddre: {"PMIP6VisitedDHCP6ServerAddress", avpBinary},
	UnassignedStart:              {"UnassignedStart", avpBinary}, //161
	//Unassigned
	UnassignedEnd:               {"UnassignedEnd", avpBinary},
	ExperimentalStart:           {"ExperimentalStart", avpBinary},
	ExperimentalEnd:             {"ExperimentalEnd", avpBinary},
	ImplementationSpecificStart: {"ImplementationSpecificStart", avpBinary},
	ImplementationSpecificEnd:   {"ImplementationSpecificEnd", avpBinary},
	ReservedStart:               {"ReservedStart", avpBinary},
	ReservedEnd:                 {"ReservedEnd", avpBinary},
}

func (a AttributeType) String() string {
	return getAttributeTypeDesc(a).name
}
