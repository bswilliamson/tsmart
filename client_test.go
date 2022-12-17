package tsmart

import (
	"context"
	"fmt"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/sys/unix"
)

type testDevice struct {
	port     string
	listener net.PacketConn
	lAddr    net.Addr
	lAddrMu  sync.Mutex
}

func newTestDevice(port string) *testDevice {
	return &testDevice{port: port}
}

func (d *testDevice) listen() {
	conf := &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(setResusePort)
		},
	}
	conn, err := conf.ListenPacket(
		context.Background(),
		"udp",
		":"+d.port,
	)
	if err != nil {
		panic(err)
	}
	d.listener = conn
}

func setResusePort(fd uintptr) {
	err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	if err != nil {
		panic(err)
	}
}

func (d *testDevice) recv(p []byte) net.Addr {
	n := len(p)
	readBytes, addr, err := d.listener.ReadFrom(p)
	if err != nil {
		panic(err)
	}
	if readBytes != n {
		panic(fmt.Sprintf("received %v bytes, want %v", readBytes, n))
	}
	return addr
}

func (d *testDevice) send(p []byte, addr net.Addr) net.Addr {
	lAddr := d.lAddr
	if lAddr == nil {
		lAddr = &net.UDPAddr{}
	}
	conn, err := net.DialUDP("udp", lAddr.(*net.UDPAddr), addr.(*net.UDPAddr))

	if err != nil {
		panic(err)
	}
	d.lAddr = conn.LocalAddr()
	defer conn.Close()

	_, err = conn.Write(p)
	if err != nil {
		panic(err)
	}
	return conn.LocalAddr()
}

func (d *testDevice) localAddr() net.Addr {
	d.lAddrMu.Lock()
	defer d.lAddrMu.Unlock()

	return d.lAddr
}

func (d *testDevice) respondToDiscovery(t *testing.T, resp []byte) {
	d.lAddrMu.Lock()
	defer d.lAddrMu.Unlock()

	discoveryPacket := []byte{
		0x01,       // command: discover
		0x00, 0x00, // sub-command: none
		0x54, // checksum
	}

	packet := make([]byte, len(discoveryPacket))
	addr := d.recv(packet)
	if !cmp.Equal(packet, discoveryPacket) {
		t.Errorf("discovery packet diff -want +got\n%v", cmp.Diff(packet, resp))
	}

	d.send(resp, addr)
}

func (d *testDevice) close() {
	d.listener.Close()
}

const discoverTimeout = 10000 * time.Millisecond

func TestDiscoverAddressErrors(t *testing.T) {
	tests := []struct {
		name string
		addr string
	}{
		{"bad address", "unknown.invalid:0"},
		{"bad port", "localhost:65536"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withTimeout(t, discoverTimeout, func() {
				client := New(tc.addr)
				_, err := client.Discover(context.Background())
				if err == nil {
					t.Error("expected error")
				}
			})
		})
	}
}

func withTimeout(t *testing.T, d time.Duration, f func()) {
	timeout := time.After(d)
	done := make(chan struct{})
	go func() {
		f()
		close(done)
	}()

	select {
	case <-timeout:
		t.Errorf("timeout")
	case <-done:
		return
	}
}

func TestDiscover(t *testing.T) {
	tt := []struct {
		name    string
		packets [][]byte
		devices []Device
	}{
		{
			name: "no devices",
		},
		{
			name: "bad checksum",
			packets: [][]byte{{
				0x01,       // command: discover
				0x00, 0x00, // sub-command: none
				0x20, 0x00, // device type: 0x0020 (water heater)
				0x26, 0xC7, 0x4D, 0x00, // device ID: 0x004DC726
				0x54, 0x45, 0x53, 0x4C, 0x41, // device name: TESLA
				0x00, 0x00, 0x00, 0x00, 0x00, // device name (null padding)
				0x00, 0x00, 0x00, 0x00, 0x00, // device name (null padding)
				0x00, 0x00, 0x00, 0x00, 0x00, // device name (null padding)
				0x00, 0x00, 0x00, 0x00, 0x00, // device name (null padding)
				0x00, 0x00, 0x00, 0x00, 0x00, // device name (null padding)
				0x00, 0x00, // device name (null padding)
				0x64, // timezone: UTC+1 (96+4)
				0x00, // checksum: incorrect
			}},
		},
		{
			name: "one device",
			packets: [][]byte{{
				0x01,       // command: discover
				0x00, 0x00, // sub-command: none
				0x20, 0x00, // device type: 0x0020 (water heater)
				0x26, 0xC7, 0x4D, 0x00, // device ID: 0x004DC726
				0x54, 0x45, 0x53, 0x4C, 0x41, // device name: TESLA
				0x00, 0x00, 0x00, 0x00, 0x00, // device name (null padding)
				0x00, 0x00, 0x00, 0x00, 0x00, // device name (null padding)
				0x00, 0x00, 0x00, 0x00, 0x00, // device name (null padding)
				0x00, 0x00, 0x00, 0x00, 0x00, // device name (null padding)
				0x00, 0x00, 0x00, 0x00, 0x00, // device name (null padding)
				0x00, 0x00, // device name (null padding)
				0x64, // timezone: UTC+1 (96+4)
				0xF3, // checksum
			}},
			devices: []Device{{
				Type:     0x0020,
				ID:       0x004DC726,
				Name:     "TESLA",
				TzOffset: time.Hour,
			}},
		},
		{
			name: "multiple devices",
			packets: [][]byte{{
				0x01,       // command: discover
				0x00, 0x00, // sub-command: none
				0x20, 0x00, // device type: 0x0020 (water heater)
				0x26, 0xC7, 0x4D, 0x00, // device ID: 0x004DC726
				0x54, 0x45, 0x53, 0x4C, 0x41, // device name: TESLA
				0x00, 0x00, 0x00, 0x00, 0x00, // device name (null padding)
				0x00, 0x00, 0x00, 0x00, 0x00, // device name (null padding)
				0x00, 0x00, 0x00, 0x00, 0x00, // device name (null padding)
				0x00, 0x00, 0x00, 0x00, 0x00, // device name (null padding)
				0x00, 0x00, 0x00, 0x00, 0x00, // device name (null padding)
				0x00, 0x00, // device name (null padding)
				0x64, // timezone: UTC+1 (96+4)
				0xF3, // checksum
			}, {
				0x01,       // command: discover
				0x00, 0x00, // sub-command: none
				0x20, 0x00, // device type: 0x0020 (water heater)
				0xFF, 0xFF, 0xFF, 0xFF, // device ID: 0x004DC726
				0x41, 0x4C, 0x53, 0x45, 0x54, // device name: ALSET
				0x00, 0x00, 0x00, 0x00, 0x00, // device name (null padding)
				0x00, 0x00, 0x00, 0x00, 0x00, // device name (null padding)
				0x00, 0x00, 0x00, 0x00, 0x00, // device name (null padding)
				0x00, 0x00, 0x00, 0x00, 0x00, // device name (null padding)
				0x00, 0x00, 0x00, 0x00, 0x00, // device name (null padding)
				0x00, 0x00, // device name (null padding)
				0x60, // timezone: UTC (96+0)
				0x5B, // checksum
			}},
			devices: []Device{{
				Type:     0x0020,
				ID:       0x004DC726,
				Name:     "TESLA",
				TzOffset: time.Hour,
			}, {
				Type:     0x0020,
				ID:       0xFFFFFFFF,
				Name:     "ALSET",
				TzOffset: 0,
			}},
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			packets := tc.packets
			devices := tc.devices
			withTimeout(t, discoverTimeout, func() {
				discoverTest(t, packets, devices)
			})
		})
	}
}

func discoverTest(t *testing.T, responsePackets [][]byte, expectedDevices []Device) {
	broadcastPort := randPort()

	client := New("255.255.255.255:" + broadcastPort)
	client.controlFunc = func(network, address string, conn syscall.RawConn) error {
		return conn.Control(setResusePort)
	}

	ctx, cancel := context.WithCancel(context.Background())
	ch, err := client.Discover(ctx)

	if err != nil {
		t.Errorf("Discover() error: %v", err)
	}

	testDevices := startTestDevices(len(responsePackets), broadcastPort)

	go func() {
		for i, resp := range responsePackets {
			tDev := testDevices[i]
			tDev.respondToDiscovery(t, resp)
			tDev.close()
		}
	}()

	for i, dev := range expectedDevices {
		resp := <-ch
		dev.Addr = testDevices[i].localAddr()
		if !cmp.Equal(dev, resp) {
			t.Errorf("Discover() diff -want +got\n%v", cmp.Diff(dev, resp))
		}
	}

	cancel()
	if <-ch != (Device{}) {
		t.Error("cancelling context did not stop discovery")
	}
}

func randPort() string {
	conn, err := net.ListenPacket("udp", "localhost:0")
	if err != nil {
		panic(err)
	}
	_, port, _ := net.SplitHostPort(conn.LocalAddr().String())
	conn.Close()
	return port
}

func startTestDevices(n int, broadcastPort string) []*testDevice {
	var testDevices []*testDevice
	for i := 0; i < n; i++ {
		dev := newTestDevice(broadcastPort)
		dev.listen()
		testDevices = append(testDevices, dev)
	}
	return testDevices
}
