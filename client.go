package tsmart

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"time"
)

var byteOrder = binary.LittleEndian

const (
	cmdDiscover = 0x01

	subcmdNone = 0x0000
)

type Client struct {
	broadcastAddr string
	controlFunc   func(network, address string, conn syscall.RawConn) error
}

type Device struct {
	Type     uint16
	ID       uint32
	Name     string
	TzOffset time.Duration
	Addr     net.Addr
}

func New(addr string) *Client {
	return &Client{
		broadcastAddr: addr,
	}
}

func (c *Client) Discover(ctx context.Context) (<-chan Device, error) {
	conf := &net.ListenConfig{Control: c.controlFunc}

	broadcastAddr, err := net.ResolveUDPAddr("udp", c.broadcastAddr)
	if err != nil {
		return nil, err
	}

	conn, err := conf.ListenPacket(
		context.Background(),
		"udp",
		fmt.Sprintf(":%d", broadcastAddr.Port),
	)
	if err != nil {
		return nil, err
	}

	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	respCh := make(chan Device)
	go c.handleDiscoveryResponses(ctx, conn, respCh)

	sendDiscoveryPacket(conn, broadcastAddr)

	return respCh, err
}

func (*Client) handleDiscoveryResponses(ctx context.Context, conn net.PacketConn, respCh chan Device) {
	packetSize := binary.Size(discoveryResponse{})

	for {
		packet := make([]byte, packetSize)

		n, addr, err := conn.ReadFrom(packet)
		switch {
		case err != nil:
			select {
			case <-ctx.Done():
				close(respCh)
				return
			default:
				panic(err)
			}
		case n != packetSize || !checksumValid(packet):
			// discard packet
			continue
		}

		readBuf := bytes.NewBuffer(packet)

		var dev discoveryResponse
		err = binary.Read(readBuf, byteOrder, &dev)
		if err != nil {
			panic(err)
		}

		name := bytes.Split(dev.Name[:], []byte{0x00})[0]

		device := Device{
			Type:     dev.Type,
			ID:       dev.ID,
			Name:     string(name),
			Addr:     addr,
			TzOffset: (time.Duration(dev.TzOffset) - 96) * 15 * time.Minute,
		}
		respCh <- device
	}
}

func sendDiscoveryPacket(conn net.PacketConn, broadcastAddr *net.UDPAddr) {
	msg := struct {
		command
		checksum
	}{
		command{
			Command:    cmdDiscover,
			Subcommand: subcmdNone,
		},
		checksum{
			Checksum: 0x54,
		},
	}

	writeBuf := &bytes.Buffer{}
	err := binary.Write(writeBuf, byteOrder, msg)
	if err != nil {
		panic(err)
	}

	_, err = conn.WriteTo(writeBuf.Bytes(), broadcastAddr)
	if err != nil {
		panic(err)
	}
}

func checksumValid(p []byte) bool {
	data := p[:len(p)-1]
	checksum := p[len(p)-1]

	var calculatedSum byte

	for _, b := range data {
		calculatedSum ^= b
	}

	calculatedSum ^= 0x55

	return calculatedSum == checksum
}
