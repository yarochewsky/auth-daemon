// Code generated by the FlatBuffers compiler. DO NOT EDIT.

package service

import "strconv"

type Payload byte

const (
	PayloadNONE                     Payload = 0
	PayloadHeartbeatRequest         Payload = 1
	PayloadHeartbeatResponse        Payload = 2
	PayloadAuthorizeProcessRequest  Payload = 3
	PayloadAuthorizeProcessResponse Payload = 4
)

var EnumNamesPayload = map[Payload]string{
	PayloadNONE:                     "NONE",
	PayloadHeartbeatRequest:         "HeartbeatRequest",
	PayloadHeartbeatResponse:        "HeartbeatResponse",
	PayloadAuthorizeProcessRequest:  "AuthorizeProcessRequest",
	PayloadAuthorizeProcessResponse: "AuthorizeProcessResponse",
}

var EnumValuesPayload = map[string]Payload{
	"NONE":                     PayloadNONE,
	"HeartbeatRequest":         PayloadHeartbeatRequest,
	"HeartbeatResponse":        PayloadHeartbeatResponse,
	"AuthorizeProcessRequest":  PayloadAuthorizeProcessRequest,
	"AuthorizeProcessResponse": PayloadAuthorizeProcessResponse,
}

func (v Payload) String() string {
	if s, ok := EnumNamesPayload[v]; ok {
		return s
	}
	return "Payload(" + strconv.FormatInt(int64(v), 10) + ")"
}
