package main

import (
	"log"
  "fmt"
  "os"
  "errors"
  "os/signal"
  "syscall"
	"net"

  flatbuffers "github.com/google/flatbuffers/go"

  "proxy-service/internal/service"
  "proxy-service/internal/access"
)

const (
  proxyAddr = "/tmp/proxy"
  serverAddr = "/tmp/process_monitor"
)

// TODO: maybe we ca use builder.Reset() to solve problem

type server struct {
  accessControl access.Store
  conn *net.UnixConn
}

func main() {
  // cleanup old files
  os.Remove(proxyAddr)

  accessStore := access.New()

  conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{proxyAddr, "unixgram"})
  if err != nil {
    log.Fatal("failed to listen on socker", err)
  }

  rawConn, err := conn.SyscallConn()
  if err != nil {
    log.Fatal("failed to retrieve raw connection", err)
  }

  err = rawConn.Control(func (fd uintptr) {
    syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_PASSCRED, 1)
  })
  if err != nil {
    log.Fatal("failed to set socket options", err)
  }

  s := &server{
    accessControl: accessStore,
    conn: conn,
  }
  // whitelist my parent because He created me
  s.accessControl.AuthorizeProcess(uint32(os.Getppid()), 0)

  fmt.Printf("Starting proxy at %d\n", os.Getpid())

  closeHandler()

  payload:= make([]byte, 1024)
  control := make([]byte, 100)

  for {
    payloadLen, controlLen, _, _, err := conn.ReadMsgUnix(payload, control)
    if err != nil {
      log.Printf("failed to receive message %v\n", err)
      continue
    }
    go s.handleConnection(payload[:payloadLen], control[:controlLen])
  }
}

func (s *server) handleConnection(payload, control []byte) {
  if len(control) == 0 {
    log.Println("received message does not have control info; dropping")
    return
  }
  if len(payload) == 0 {
    log.Println("no payload received")
    return
  }
  log.Printf("handling message: payload len: %d, control len: %d\n", len(payload), len(control))

  ok, err := s.verifyCredentials(control)
  if err != nil {
    log.Printf("could not verify credentials: %v\n", err)
    return
  }
  if !ok {
    log.Println("unauthorized request")
    return
  }

  if err = s.dispatcher(payload); err != nil {
    log.Printf("handler failed: %v\n", err)
  }
}

func closeHandler() {
  c := make(chan os.Signal)
  signal.Notify(c, os.Interrupt, syscall.SIGTERM)
  go func() {
    <-c
    fmt.Println("cleanin up")
    os.Remove(proxyAddr)
    os.Exit(0)
  }()
}

func (s *server) send(buf []byte) error {
  addr, err := net.ResolveUnixAddr("unixgram", serverAddr)
  if err != nil {
    return err
  }

  _, err = s.conn.WriteToUnix(buf, addr)

  return err
}

func (s *server) newHeartbeatResponse(seqNum uint64) []byte {
  b := flatbuffers.NewBuilder(1024)
  service.HeartbeatResponseStart(b)
  hb := service.HeartbeatResponseEnd(b)

  service.MessageStart(b)
  service.MessageAddPayloadType(b, service.PayloadHeartbeatResponse)
  service.MessageAddPayload(b, hb)
  service.MessageAddSeqNum(b, seqNum)
  m := service.MessageEnd(b)

  b.Finish(m)
  return b.FinishedBytes()
}

func (s *server) newHeartbeatRequest(seqNum uint64) []byte {
  b := flatbuffers.NewBuilder(1024)
  service.HeartbeatRequestStart(b)
  hb := service.HeartbeatRequestEnd(b)

  service.MessageStart(b)
  service.MessageAddPayloadType(b, service.PayloadHeartbeatRequest)
  service.MessageAddPayload(b, hb)
  service.MessageAddSeqNum(b, seqNum)
  m := service.MessageEnd(b)

  b.Finish(m)
  return b.FinishedBytes()
}

func (s *server) newAuthorizeProcessResponse(seqNum uint64) []byte {
  b := flatbuffers.NewBuilder(1024)
  service.AuthorizeProcessResponseStart(b)
  ar := service.AuthorizeProcessResponseEnd(b)

  service.MessageStart(b)
  service.MessageAddPayloadType(b, service.PayloadAuthorizeProcessResponse)
  service.MessageAddPayload(b, ar)
  service.MessageAddSeqNum(b, seqNum)
  m := service.MessageEnd(b)

  b.Finish(m)
  return b.FinishedBytes()
}

func (s *server) handleHeartbeat(req *service.HeartbeatRequest, seq uint64) error {
  log.Printf("proxy: handling heartbeat request: %d\n", seq)

  resp := s.newHeartbeatResponse(seq)
  return s.send(resp)
}

func (s *server) handleAuthorizeProcess(req *service.AuthorizeProcessRequest, seq uint64) error {
  s.accessControl.AuthorizeProcess(req.NewPid(), req.OldPid())
  log.Printf("proxy: handling authorization swap from %d to %d\n", req.OldPid(), req.NewPid())

  resp := s.newAuthorizeProcessResponse(seq)
  return s.send(resp)
}

func (s *server) dispatcher(payload []byte) error {
  msg := service.GetRootAsMessage(payload, 0)
  seqNum := msg.SeqNum()
  payloadUnion := msg.Table()

  if msg.Payload(&payloadUnion) {
    switch(msg.PayloadType()) {
      case service.PayloadHeartbeatRequest:
        req := new(service.HeartbeatRequest)
        req.Init(payloadUnion.Bytes, payloadUnion.Pos)
        return s.handleHeartbeat(req, seqNum)
      case service.PayloadAuthorizeProcessRequest:
        req := new(service.AuthorizeProcessRequest)
        req.Init(payloadUnion.Bytes, payloadUnion.Pos)
        return s.handleAuthorizeProcess(req, seqNum)
      default:
        return errors.New("invalid request")
    }
  }
  return errors.New("error reading payload")
}

func (s *server) verifyCredentials(control []byte) (bool, error) {
    scms, err := syscall.ParseSocketControlMessage(control)
    if err != nil {
      return false, err
    }

    if len(scms) <= 0 {
      return false, errors.New("invalid control message")
    }

    ucred, err := syscall.ParseUnixCredentials(&scms[0])
    if err != nil {
      return false, err
    }
    pid, _, _ := ucred.Pid, ucred.Uid, ucred.Gid
    return s.accessControl.IsAuthorized(uint32(pid)), nil
}
