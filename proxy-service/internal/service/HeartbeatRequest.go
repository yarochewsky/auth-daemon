// Code generated by the FlatBuffers compiler. DO NOT EDIT.

package service

import (
	flatbuffers "github.com/google/flatbuffers/go"
)

type HeartbeatRequest struct {
	_tab flatbuffers.Table
}

func GetRootAsHeartbeatRequest(buf []byte, offset flatbuffers.UOffsetT) *HeartbeatRequest {
	n := flatbuffers.GetUOffsetT(buf[offset:])
	x := &HeartbeatRequest{}
	x.Init(buf, n+offset)
	return x
}

func (rcv *HeartbeatRequest) Init(buf []byte, i flatbuffers.UOffsetT) {
	rcv._tab.Bytes = buf
	rcv._tab.Pos = i
}

func (rcv *HeartbeatRequest) Table() flatbuffers.Table {
	return rcv._tab
}

func HeartbeatRequestStart(builder *flatbuffers.Builder) {
	builder.StartObject(0)
}
func HeartbeatRequestEnd(builder *flatbuffers.Builder) flatbuffers.UOffsetT {
	return builder.EndObject()
}
