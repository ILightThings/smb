package enum

import (
	"encoding/binary"

	"github.com/ilightthings/smb/smb"
)

type workstaion struct {
	signature        []byte // 8 Bytes 32
	messsagetype     []byte // 4 Bytes 16
	TargetNameFields []byte // 8 bytes 32
	NegotiateFlags   []byte // 4 bytes 16
	ServerChallenge  []byte // 8 bytes 32
	Reserve          []byte // 8 bytes 32
	TargetInfoFields []byte // 8 bytes 32
	TargetInfoLength int
	TargetInfoMaxlen int
	TargetInfoOffset int
	Version          []byte // 8 Bytes 32 Windows OS would be here
	Payload          []byte // Unknow Number of bytes

}

func BuildWorkstation(s *smb.Session) workstaion {
	rawBuild := s.Blob.ResponseToken
	var workstationInfo workstaion
	workstationInfo.signature = rawBuild[0:8]
	workstationInfo.messsagetype = rawBuild[8:12]
	workstationInfo.TargetNameFields = rawBuild[12:20]
	workstationInfo.NegotiateFlags = rawBuild[20:24]
	workstationInfo.ServerChallenge = rawBuild[24:32]
	workstationInfo.Reserve = rawBuild[32:40]
	workstationInfo.TargetInfoFields = rawBuild[40:48]
	workstationInfo.TargetInfoLength = int(binary.LittleEndian.Uint16(workstationInfo.TargetInfoFields[0:2]))
	workstationInfo.TargetInfoMaxlen = int(binary.LittleEndian.Uint16(workstationInfo.TargetInfoFields[2:4]))
	workstationInfo.TargetInfoOffset = int(binary.LittleEndian.Uint16(workstationInfo.TargetInfoFields[4:8]))
	workstationInfo.Version = rawBuild[48:56]
	workstationInfo.Payload = rawBuild[56:]
	return workstationInfo

}
