package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// packetTransport abstracts datagram-like transport between peers.
type packetTransport interface {
	WriteTo(b []byte, addr net.Addr) (int, error)
	ReadFrom(b []byte) (int, net.Addr, error)
	Close() error
}

// tcpFramedTransport turns a TCP stream into framed packetTransport.
type tcpFramedTransport struct {
	conn net.Conn
	mu   sync.Mutex
}

func newTCPFramedTransport(conn net.Conn) *tcpFramedTransport {
	return &tcpFramedTransport{conn: conn}
}

func (t *tcpFramedTransport) WriteTo(b []byte, _ net.Addr) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(b)))
	if _, err := t.conn.Write(lenBuf[:]); err != nil {
		return 0, err
	}
	n, err := t.conn.Write(b)
	return n, err
}

func (t *tcpFramedTransport) ReadFrom(b []byte) (int, net.Addr, error) {
	var lenBuf [4]byte
	if _, err := ioReadFull(t.conn, lenBuf[:]); err != nil {
		return 0, nil, err
	}
	l := binary.BigEndian.Uint32(lenBuf[:])
	if int(l) > len(b) {
		return 0, nil, fmt.Errorf("frame too large: %d", l)
	}
	if _, err := ioReadFull(t.conn, b[:l]); err != nil {
		return 0, nil, err
	}
	return int(l), t.conn.RemoteAddr(), nil
}

func (t *tcpFramedTransport) Close() error { return t.conn.Close() }

func ioReadFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

type udpTransport struct{ conn *net.UDPConn }

func (t *udpTransport) WriteTo(b []byte, addr net.Addr) (int, error) { return t.conn.WriteTo(b, addr) }
func (t *udpTransport) ReadFrom(b []byte) (int, net.Addr, error)     { return t.conn.ReadFrom(b) }
func (t *udpTransport) Close() error                                 { return t.conn.Close() }

type icmpTransport struct {
	conn   *icmp.PacketConn
	remote net.Addr
}

func (t *icmpTransport) WriteTo(b []byte, _ net.Addr) (int, error) {
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{ID: 0x6b6f, Seq: 0, Data: b},
	}
	data, err := msg.Marshal(nil)
	if err != nil {
		return 0, err
	}
	return t.conn.WriteTo(data, t.remote)
}

func (t *icmpTransport) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := t.conn.ReadFrom(b)
	if err != nil {
		return 0, nil, err
	}
	parsed, err := icmp.ParseMessage(int(ipv4.ICMPTypeEcho.Protocol()), b[:n])
	if err != nil {
		return 0, nil, err
	}
	if parsed.Type != ipv4.ICMPTypeEcho && parsed.Type != ipv4.ICMPTypeEchoReply {
		return 0, nil, errors.New("unexpected icmp message")
	}
	echo, ok := parsed.Body.(*icmp.Echo)
	if !ok {
		return 0, nil, errors.New("invalid icmp payload")
	}
	copy(b, echo.Data)
	return len(echo.Data), addr, nil
}

func (t *icmpTransport) Close() error { return t.conn.Close() }

func newClientTransport(rawMode string, local, remote string) (packetTransport, net.Addr, error) {
	switch strings.ToLower(rawMode) {
	case "udp":
		r := mustResolve(remote)
		conn, err := net.DialUDP("udp", nil, r)
		if err != nil {
			return nil, nil, err
		}
		return &udpTransport{conn: conn}, r, nil
	case "icmp":
		ipRemote := ipOnly(remote)
		conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		if err != nil {
			return nil, nil, err
		}
		addr := &net.IPAddr{IP: net.ParseIP(ipRemote)}
		return &icmpTransport{conn: conn, remote: addr}, addr, nil
	case "faketcp", "easy-faketcp":
		conn, err := net.Dial("tcp", remote)
		if err != nil {
			return nil, nil, err
		}
		return newTCPFramedTransport(conn), conn.RemoteAddr(), nil
	default:
		return nil, nil, fmt.Errorf("unsupported raw-mode %s", rawMode)
	}
}

// newServerUDPTransport listens on udp.
func newServerUDPTransport(local string) (packetTransport, error) {
	conn, err := net.ListenUDP("udp", mustResolve(local))
	if err != nil {
		return nil, err
	}
	return &udpTransport{conn: conn}, nil
}

func newServerICMPTransport(local string) (packetTransport, error) {
	ip := ipOnly(local)
	conn, err := icmp.ListenPacket("ip4:icmp", ip)
	if err != nil {
		return nil, err
	}
	return &icmpTransport{conn: conn}, nil
}

func ipOnly(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// tcpListener wraps accepted tcp connections as framed transports.
type tcpListener struct {
	ln net.Listener
}

func newTCPListener(local string) (*tcpListener, error) {
	ln, err := net.Listen("tcp", local)
	if err != nil {
		return nil, err
	}
	return &tcpListener{ln: ln}, nil
}

func (t *tcpListener) AcceptTransport() (*tcpFramedTransport, error) {
	conn, err := t.ln.Accept()
	if err != nil {
		return nil, err
	}
	return newTCPFramedTransport(conn), nil
}

func (t *tcpListener) Close() error { return t.ln.Close() }

// combine for tcp framed write helper.
