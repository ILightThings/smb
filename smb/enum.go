package smb

import (
	"github.com/ilightthings/smb/smb"
)

type workstaion struct {
	signature        []byte // 8 Bytes
	messsagetype     []byte // 4 Bytes
	TargetNameFields []byte // 8 bytes
	NegotiateFlags   []byte // 4 bytes
	ServerChallenge  []byte // 8 bytes
	Reserve          []byte // 8 bytes
	TargetInfoFields []byte // 8 bytes
	Version          []byte // 8 Bytes - Windows OS would be here
	Payload          []byte // Unknow Number of bytes

}

func Dissect(s *smb.Session) {

}
