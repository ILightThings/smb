package enum

import (
	"encoding/binary"
	"errors"
	"log"

	"github.com/ilightthings/smb/smb"
)

const (
	NTLMSSP_AV_EOL              = 0x00
	NTLMSSP_AV_HOSTNAME         = 0x01
	NTLMSSP_AV_DOMAINNAME       = 0x02
	NTLMSSP_AV_DNS_HOSTNAME     = 0x03
	NTLMSSP_AV_DNS_DOMAINNAME   = 0x04
	NTLMSSP_AV_DNS_TREENAME     = 0x05
	NTLMSSP_AV_FLAGS            = 0x06
	NTLMSSP_AV_TIME             = 0x07
	NTLMSSP_AV_RESTRICTIONS     = 0x08
	NTLMSSP_AV_TARGET_NAME      = 0x09
	NTLMSSP_AV_CHANNEL_BINDINGS = 0x0a
)

type workstaion struct {
	Signature              []byte // 8 Bytes 32
	Messsagetype           []byte // 4 Bytes 16
	TargetNameFields       []byte // 8 bytes 32
	TargetNameFieldsLength int
	TargetNameFieldsMaxLen int
	TargetNameFieldsOffset int
	TargetNameFieldsName   string
	NegotiateFlags         []byte // 4 bytes 16
	ServerChallenge        []byte // 8 bytes 32
	Reserve                []byte // 8 bytes 32
	TargetInfoFields       []byte // 8 bytes 32
	TargetInfoLength       int
	TargetInfoMaxlen       int
	TargetInfoOffset       int
	Version                []byte // 8 Bytes 32 Windows OS would be here
	Payload                []byte // Unknow Number of bytes
	PayloadUint16          []uint16
	NBCompName             AVPairs
	NBDomainName           AVPairs
	DNSCompName            AVPairs
	DNSDomainName          AVPairs
}

type AVPairs struct {
	Attribute     string
	AttrubuteType uint16
	AttributePos  int
	ValueRaw      []uint16
	Value         string
	ValueLen      int
}

func BuildWorkstation(s *smb.Session) workstaion {
	rawBuild := s.Blob.ResponseToken
	var workstationInfo workstaion
	var err error
	workstationInfo.Signature = rawBuild[0:8]
	workstationInfo.Messsagetype = rawBuild[8:12]
	workstationInfo.TargetNameFields = rawBuild[12:20]
	workstationInfo.TargetNameFieldsLength = int(binary.LittleEndian.Uint16(workstationInfo.TargetNameFields[0:2]))
	workstationInfo.TargetNameFieldsMaxLen = int(binary.LittleEndian.Uint16(workstationInfo.TargetNameFields[2:4]))
	workstationInfo.TargetNameFieldsOffset = int(binary.LittleEndian.Uint16(workstationInfo.TargetNameFields[4:8]))
	workstationInfo.NegotiateFlags = rawBuild[20:24]
	workstationInfo.ServerChallenge = rawBuild[24:32]
	workstationInfo.Reserve = rawBuild[32:40]
	workstationInfo.TargetInfoFields = rawBuild[40:48]
	workstationInfo.TargetInfoLength = int(binary.LittleEndian.Uint16(workstationInfo.TargetInfoFields[0:2]))
	workstationInfo.TargetInfoMaxlen = int(binary.LittleEndian.Uint16(workstationInfo.TargetInfoFields[2:4]))
	workstationInfo.TargetInfoOffset = int(binary.LittleEndian.Uint16(workstationInfo.TargetInfoFields[4:8]))
	workstationInfo.Version = rawBuild[48:56]
	workstationInfo.Payload = rawBuild[56:]
	workstationInfo.PayloadUint16 = eightToSixteen(rawBuild[56:])
	workstationInfo.TargetNameFieldsName = uint16ToString(workstationInfo.PayloadUint16[:(workstationInfo.TargetNameFieldsLength / 2)]) // Divide by 2 to converst uint8 to uint16
	workstationInfo.NBDomainName, err = extractAV(workstationInfo.PayloadUint16, uint16(NTLMSSP_AV_DOMAINNAME))
	if err != nil {
		log.Fatalln("Could not find NBDomainName")
	}
	workstationInfo.NBCompName, err = extractAV(workstationInfo.PayloadUint16, uint16(NTLMSSP_AV_HOSTNAME))
	if err != nil {
		log.Fatalln("Could not find NBHostname")
	}

	workstationInfo.DNSDomainName, err = extractAV(workstationInfo.PayloadUint16, uint16(NTLMSSP_AV_DNS_DOMAINNAME))
	if err != nil {
		log.Fatalln("Could not find DNSDomainName")
	}
	workstationInfo.DNSCompName, err = extractAV(workstationInfo.PayloadUint16, uint16(NTLMSSP_AV_DNS_HOSTNAME))
	if err != nil {
		log.Fatalln("Could not find DNSHostName")
	}

	// Attribute/Value pairs start with byte. AV PAIRS
	// https://github.com/SecureAuthCorp/impacket/blob/6042675a6c3632133ad4f932431aa96c5da5de5c/impacket/ntlm.py#L197
	// https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-NLMP/%5bMS-NLMP%5d.pdf PAGE 31
	// 2 byte identifyier
	//

	return workstationInfo

}

/* func uinteightToString(b []byte) string { //Convert []uint8 to []uint16 to []byte to string. I know I am stupid. I have no idea how to fix this otherwise.
	var niceArray []byte
	for i := 0; i <= len(b); i = i + 2 {
		val := binary.LittleEndian.Uint16(b[i : i+2])
		niceArray = append(niceArray, byte(val))
	}
	return string(niceArray)
} */

func uint16ToString(i []uint16) string {
	var byteArray []byte
	for _, y := range i {
		byteArray = append(byteArray, byte(y))
	}
	return string(byteArray)
}

func eightToSixteen(b []byte) []uint16 { //Convert []uint8 to []uint16 to []byte to string. I know I am stupid. I have no idea how to fix this otherwise.
	var deserialized []uint16
	for i := 0; i <= len(b)-2; i = i + 2 {
		val := binary.LittleEndian.Uint16(b[i : i+2])
		deserialized = append(deserialized, val)
	}
	return deserialized
}

func extractAV(s []uint16, value uint16) (AVPairs, error) { // return stating pos, len, valueRaw, value
	var AVPairObj AVPairs
	AVPairObj.AttrubuteType = value
	outOfBound := len(s) + 1
	AVPairObj.ValueLen = outOfBound

	/* 	var AttributePos int
	   	var AttributeLen int
	   	var ValueRaw []uint16
	   	var ValueString string */
	for x, y := range s {
		if y == value {
			AVPairObj.AttributePos = x
			break
		}
	}
	if AVPairObj.AttributePos == outOfBound {
		return AVPairObj, errors.New("could not find attribute location")
	}

	//AttributeLen = int(s[AttributePos])
	AVPairObj.ValueLen = int(s[AVPairObj.AttributePos+1] / 2)                                            //Uint8 to uint16 conversion
	AVPairObj.ValueRaw = s[AVPairObj.AttributePos+2 : (AVPairObj.AttributePos + 2 + AVPairObj.ValueLen)] // Plus 2 to account for the Attribute uint16 and Len uint16
	AVPairObj.Value = uint16ToString(AVPairObj.ValueRaw)

	return AVPairObj, nil

}
