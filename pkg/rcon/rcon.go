package rcon

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

type packetType uint32

const authType packetType = 3
const authResponseType packetType = 2

const execType = 2
const responseType = 0

type packet struct {
	// The packet id field is a 32-bit little endian integer chosen by the client for each request.
	id int32
	// The packet type field is a 32-bit little endian integer, which indicates the purpose of the packet.
	// Its value will always be either 0, 2, or 3
	kind packetType // type according to spec
	// The packet body field is a null-terminated string encoded in ASCII (i.e. ASCIIZ).
	// Go uses utf-8 to encode strings, which is backwards compatible to ASCII. If a non ASCII
	// character is included it will be transmitted anyway.
	body string
}

func (p *packet) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer

	err := binary.Write(&buf, binary.LittleEndian, p.id)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal packet id: %w", err)
	}

	err = binary.Write(&buf, binary.LittleEndian, int32(p.kind))
	if err != nil {
		return nil, fmt.Errorf("unable to marshal packet type: %w", err)
	}

	err = binary.Write(&buf, binary.LittleEndian, []byte(p.body))
	if err != nil {
		return nil, fmt.Errorf("unable to marshal package body: %w", err)
	}

	pad := int16(0)
	err = binary.Write(&buf, binary.LittleEndian, pad)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal package termination: %w", err)
	}

	return buf.Bytes(), nil
}

func (p *packet) UnmarshalBinary(data []byte) error {
	if len(data) < 10 {
		return fmt.Errorf("rcon package needs at least 10 bytes")
	}
	p.id = int32(binary.LittleEndian.Uint32(data[0:]))
	p.kind = packetType(int32(binary.LittleEndian.Uint32(data[4:])))
	p.body = string(data[8:])
	return nil
}

type Client struct {
	conn     net.Conn
	password string
}

// dialOptions configure a Dial call. dialOptions are set by the DialOption
// values passed to Dial.
type dialOptions struct {
	password string
}

// DialOption configures how we set up the connection.
type DialOption interface {
	apply(*dialOptions)
}

// dialOptionFunc wraps a function that modifies dialOptions into an
// implementation of the DialOption interface.
type dialOptionFunc func(*dialOptions)

func (f dialOptionFunc) apply(do *dialOptions) {
	f(do)
}

// WithPassword returns a DialOption whith the password set
func WithPassword(pw string) DialOption {
	return dialOptionFunc(func(o *dialOptions) {
		o.password = pw
	})
}

func Dial(target string, opts ...DialOption) (*Client, error) {
	return DialContext(context.Background(), target, opts...)
}

func DialContext(ctx context.Context, target string, opts ...DialOption) (*Client, error) {
	do := dialOptions{}
	for _, o := range opts {
		o.apply(&do)
	}

	var d net.Dialer // Todo timeouts?
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, err
	}

	c := Client{
		conn:     conn,
		password: do.password,
	}

	err = c.Authenticate()

	return &c, err
}

func (c Client) Authenticate() error {
	p := packet{
		id:   42, // TODO: some kind of id handeling
		kind: authType,
		body: c.password,
	}
	err := c.send(p)
	if err != nil {
		return err
	}

	resp, err := c.receive()
	if err != nil {
		return err
	}

	if resp.kind != authResponseType {
		resp, err = c.receive()
		if err != nil {
			return err
		}
		if resp.kind != authResponseType {
			return fmt.Errorf("connection establishment failed")
		}
	}

	if resp.id == -1 {
		return fmt.Errorf("unauthorized")
	}
	if resp.id != p.id {
		return fmt.Errorf("protocol error")
	}
	return nil
}

func (c Client) Command(cmd string) (string, error) {
	p := packet{
		id:   42, // TODO: some kind of id handeling
		kind: execType,
		body: cmd,
	}
	err := c.send(p)
	if err != nil {
		return "", err
	}

	resp, err := c.receive()
	if err != nil {
		return "", err
	}
	if resp.kind != responseType || resp.id != p.id {
		return "", fmt.Errorf("protocol error")
	}
	return resp.body, nil
}

func (c Client) send(p packet) error {
	b, err := p.MarshalBinary()
	if err != nil {
		return fmt.Errorf("error marshaling packet: %w", err)
	}
	// The packet size  is a 32-bit little endian integer, representing the length of the request in bytes.
	// Note that the packet size field itself is not included when determining the size of the packet
	// The maximum possible value of packet size is 4096
	size := int32(len(b))
	if size > 4096 {
		return fmt.Errorf("message too large: message size %d, maximum size 4096", size)
	}
	err = binary.Write(c.conn, binary.LittleEndian, size)
	if err != nil {
		return fmt.Errorf("unable to send message size: %w", err)
	}
	_, err = c.conn.Write(b)
	if err != nil {
		return fmt.Errorf("error sending packet: %w", err)
	}
	return nil
}

func (c Client) receive() (packet, error) {
	p := packet{}

	var size int32
	err := binary.Read(c.conn, binary.LittleEndian, &size)
	if err != nil {
		return p, err
	}

	buf := make([]byte, size)
	_, err = io.ReadFull(c.conn, buf)
	if err != nil {
		return p, err
	}

	err = p.UnmarshalBinary(buf)

	return p, err
}
