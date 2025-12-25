package tunnel

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	cfgpkg "udp2raw-go/internal/config"
	cryptopkg "udp2raw-go/internal/crypto"
)

const (
	magic   = 0x75703272 // "up2r"
	version = 1

	flagHeartbeat = 0x1
)

// Session handles encryption/auth and sequencing for a peer.
type Session struct {
	encKeys  *cryptopkg.Keys
	decKeys  *cryptopkg.Keys
	cipher   cryptopkg.CipherMode
	auth     cryptopkg.AuthMode
	sendSeq  uint64
	replay   *AntiReplay
	encBlock cipher.Block
	decBlock cipher.Block
}

func NewSession(secret string, isClient bool, cipherMode string, authMode string) (*Session, error) {
	enc, dec, err := cryptopkg.DeriveKeys(secret, isClient)
	if err != nil {
		return nil, err
	}
	encBlock, err := cryptopkg.PrepareBlock(enc, cryptopkg.CipherMode(cipherMode))
	if err != nil {
		return nil, err
	}
	decBlock, err := cryptopkg.PrepareBlock(dec, cryptopkg.CipherMode(cipherMode))
	if err != nil {
		return nil, err
	}
	return &Session{
		encKeys:  enc,
		decKeys:  dec,
		cipher:   cryptopkg.CipherMode(cipherMode),
		auth:     cryptopkg.AuthMode(authMode),
		replay:   NewAntiReplay(64),
		encBlock: encBlock,
		decBlock: decBlock,
	}, nil
}

// Frame is the plaintext payload exchanged between peers.
type Frame struct {
	Seq     uint64
	FlowID  uint32
	Flags   uint8
	Payload []byte
}

func (s *Session) MarshalFrame(f Frame) ([]byte, error) {
	seq := atomic.AddUint64(&s.sendSeq, 1)

	header := make([]byte, 4+1+8+4+1+2)
	binary.BigEndian.PutUint32(header[0:4], magic)
	header[4] = version
	binary.BigEndian.PutUint64(header[5:13], seq)
	binary.BigEndian.PutUint32(header[13:17], f.FlowID)
	header[17] = f.Flags
	if len(f.Payload) > 0xFFFF {
		return nil, errors.New("payload too large")
	}
	binary.BigEndian.PutUint16(header[18:20], uint16(len(f.Payload)))
	plain := append(header, f.Payload...)
	return cryptopkg.EncryptWithBlock(plain, s.encKeys, s.cipher, s.auth, s.encBlock)
}

func (s *Session) UnmarshalFrame(b []byte) (Frame, error) {
	var frame Frame
	plain, err := cryptopkg.DecryptWithBlock(b, s.decKeys, s.cipher, s.auth, s.decBlock)
	if err != nil {
		return frame, err
	}
	if len(plain) < 20 {
		return frame, errors.New("frame too short")
	}
	if binary.BigEndian.Uint32(plain[0:4]) != magic {
		return frame, errors.New("invalid magic")
	}
	if plain[4] != version {
		return frame, errors.New("unsupported version")
	}
	seq := binary.BigEndian.Uint64(plain[5:13])
	if !s.replay.Check(seq) {
		return frame, errors.New("replay detected")
	}
	frame.Seq = seq
	frame.FlowID = binary.BigEndian.Uint32(plain[13:17])
	frame.Flags = plain[17]
	l := binary.BigEndian.Uint16(plain[18:20])
	if int(20+l) != len(plain) {
		return frame, errors.New("invalid length")
	}
	frame.Payload = plain[20:]
	return frame, nil
}

// Run starts the tunnel based on config.
func Run(cfg *cfgpkg.Config, logger *log.Logger) error {
	session, err := NewSession(cfg.Key, cfg.Mode == cfgpkg.Client, cfg.CipherMode, cfg.AuthMode)
	if err != nil {
		return err
	}

	switch cfg.Mode {
	case cfgpkg.Client:
		return runClient(cfg, session, logger)
	case cfgpkg.Server:
		return runServer(cfg, session, logger)
	default:
		return fmt.Errorf("unknown mode")
	}
}

func runClient(cfg *cfgpkg.Config, session *Session, logger *log.Logger) error {
	localUDP, err := net.ListenUDP("udp", mustResolve(cfg.Local))
	if err != nil {
		return fmt.Errorf("listen local udp: %w", err)
	}
	defer localUDP.Close()

	transportConn, remoteAddr, err := newClientTransport(cfg.RawMode, cfg.Local, cfg.Remote)
	if err != nil {
		return fmt.Errorf("create client transport: %w", err)
	}
	defer transportConn.Close()

	flows := NewFlowTable()
	// map peer addr string -> flow id
	addrToID := make(map[string]uint32)
	addrMu := sync.Mutex{}

	go sendHeartbeatsPacket(session, transportConn, logger, 0, remoteAddr)

	// receive from transport -> forward to local app
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, addr, err := transportConn.ReadFrom(buf)
			if err != nil {
				logger.Printf("transport read error: %v", err)
				return
			}
			frame, err := session.UnmarshalFrame(buf[:n])
			if err != nil {
				logger.Printf("frame decode error: %v", err)
				continue
			}
			if frame.Flags&flagHeartbeat != 0 {
				continue
			}
			flow, ok := flows.Get(frame.FlowID)
			if !ok {
				logger.Printf("unknown flow %d from server %v", frame.FlowID, addr)
				continue
			}
			flows.Touch(flow.ID)
			if len(frame.Payload) == 0 {
				continue
			}
			if _, err := localUDP.WriteToUDP(frame.Payload, flow.PeerAddr); err != nil {
				logger.Printf("write to local failed: %v", err)
			}
		}
	}()

	buf := make([]byte, 64*1024)
	for {
		n, addr, err := localUDP.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		addrKey := addr.String()
		addrMu.Lock()
		flowID, ok := addrToID[addrKey]
		if !ok {
			// create new flow placeholder
			flow := flows.Add(addr, nil, 0)
			flowID = flow.ID
			addrToID[addrKey] = flowID
		}
		addrMu.Unlock()

		payload := append([]byte(nil), buf[:n]...)
		cipherText, err := session.MarshalFrame(Frame{FlowID: flowID, Payload: payload})
		if err != nil {
			logger.Printf("marshal frame error: %v", err)
			continue
		}
		if _, err := transportConn.WriteTo(cipherText, remoteAddr); err != nil {
			logger.Printf("send frame error: %v", err)
		}
	}
}

func runServer(cfg *cfgpkg.Config, session *Session, logger *log.Logger) error {
	backendAddr := mustResolve(cfg.Remote)
	flows := NewFlowTable()

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		for range ticker.C {
			flows.Cleanup(5 * time.Minute)
		}
	}()

	switch strings.ToLower(cfg.RawMode) {
	case "faketcp", "easy-faketcp":
		return serveTCP(cfg, session, logger, flows, backendAddr)
	case "icmp":
		return servePacket(cfg, session, logger, flows, backendAddr, "icmp")
	case "udp":
		return servePacket(cfg, session, logger, flows, backendAddr, "udp")
	default:
		return fmt.Errorf("unsupported raw-mode %s", cfg.RawMode)
	}
}

func serveTCP(cfg *cfgpkg.Config, session *Session, logger *log.Logger, flows *FlowTable, backendAddr *net.UDPAddr) error {
	ln, err := newTCPListener(cfg.Local)
	if err != nil {
		return fmt.Errorf("listen tcp: %w", err)
	}
	defer ln.Close()

	for {
		t, err := ln.AcceptTransport()
		if err != nil {
			return err
		}
		go handleTCPConn(t, session, logger, flows, backendAddr)
	}
}

func handleTCPConn(tp *tcpFramedTransport, session *Session, logger *log.Logger, flows *FlowTable, backendAddr *net.UDPAddr) {
	defer tp.Close()
	buf := make([]byte, 64*1024)
	for {
		n, addr, err := tp.ReadFrom(buf)
		if err != nil {
			logger.Printf("tcp transport read error: %v", err)
			return
		}
		frame, err := session.UnmarshalFrame(buf[:n])
		if err != nil {
			logger.Printf("frame decode error: %v", err)
			continue
		}
		udpAddr, _ := net.ResolveUDPAddr("udp", addr.String())
		if frame.Flags&flagHeartbeat != 0 {
			reply, err := session.MarshalFrame(Frame{Seq: frame.Seq, FlowID: frame.FlowID, Flags: flagHeartbeat})
			if err == nil {
				_, _ = tp.WriteTo(reply, addr)
			}
			continue
		}
		flow, ok := flows.Get(frame.FlowID)
		if !ok {
			backend, err := net.DialUDP("udp", nil, backendAddr)
			if err != nil {
				logger.Printf("dial backend failed: %v", err)
				continue
			}
			flow = flows.Add(udpAddr, backend, frame.FlowID)
			go pumpBackend(flow, session, tp, logger, addr)
		}
		flows.Touch(flow.ID)
		if len(frame.Payload) == 0 {
			continue
		}
		if _, err := flow.Backend.Write(frame.Payload); err != nil {
			logger.Printf("write to backend failed: %v", err)
		}
	}
}

func servePacket(cfg *cfgpkg.Config, session *Session, logger *log.Logger, flows *FlowTable, backendAddr *net.UDPAddr, mode string) error {
	var transport packetTransport
	var err error
	if mode == "icmp" {
		transport, err = newServerICMPTransport(cfg.Local)
	} else {
		transport, err = newServerUDPTransport(cfg.Local)
	}
	if err != nil {
		return fmt.Errorf("listen transport: %w", err)
	}
	defer transport.Close()

	buf := make([]byte, 64*1024)
	for {
		n, addr, err := transport.ReadFrom(buf)
		if err != nil {
			return err
		}
		frame, err := session.UnmarshalFrame(buf[:n])
		if err != nil {
			logger.Printf("frame decode error: %v", err)
			continue
		}
		udpAddr, _ := net.ResolveUDPAddr("udp", addr.String())
		if frame.Flags&flagHeartbeat != 0 {
			reply, err := session.MarshalFrame(Frame{Seq: frame.Seq, FlowID: frame.FlowID, Flags: flagHeartbeat})
			if err == nil {
				_, _ = transport.WriteTo(reply, addr)
			}
			continue
		}
		flow, ok := flows.Get(frame.FlowID)
		if !ok {
			backend, err := net.DialUDP("udp", nil, backendAddr)
			if err != nil {
				logger.Printf("dial backend failed: %v", err)
				continue
			}
			flow = flows.Add(udpAddr, backend, frame.FlowID)
			go pumpBackend(flow, session, transport, logger, addr)
		}
		flows.Touch(flow.ID)
		if len(frame.Payload) == 0 {
			continue
		}
		if _, err := flow.Backend.Write(frame.Payload); err != nil {
			logger.Printf("write to backend failed: %v", err)
		}
	}
}

func pumpBackend(flow *Flow, session *Session, transport packetTransport, logger *log.Logger, remote net.Addr) {
	buf := make([]byte, 64*1024)
	for {
		n, err := flow.Backend.Read(buf)
		if err != nil {
			logger.Printf("backend read failed: %v", err)
			return
		}
		cipherText, err := session.MarshalFrame(Frame{FlowID: flow.ID, Payload: buf[:n]})
		if err != nil {
			logger.Printf("marshal frame error: %v", err)
			continue
		}
		if _, err := transport.WriteTo(cipherText, remote); err != nil {
			logger.Printf("send to client failed: %v", err)
		}
	}
}

func sendHeartbeatsPacket(session *Session, transport packetTransport, logger *log.Logger, flowID uint32, remote net.Addr) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		frame := Frame{FlowID: flowID, Flags: flagHeartbeat}
		data, err := session.MarshalFrame(frame)
		if err != nil {
			logger.Printf("heartbeat marshal failed: %v", err)
			continue
		}
		if _, err := transport.WriteTo(data, remote); err != nil {
			logger.Printf("heartbeat send failed: %v", err)
			return
		}
	}
}

func mustResolve(addr string) *net.UDPAddr {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		panic(err)
	}
	return udpAddr
}
