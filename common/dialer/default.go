package dialer

import (
	"context"
	"net"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/conntrack"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var ConcurrentDial bool

var _ WireGuardListener = (*DefaultDialer)(nil)

type DefaultDialer struct {
	dialer4             tcpDialer
	dialer6             tcpDialer
	udpDialer4          net.Dialer
	udpDialer6          net.Dialer
	udpListener         net.ListenConfig
	udpAddr4            string
	udpAddr6            string
	isWireGuardListener bool
}

func NewDefault(router adapter.Router, options option.DialerOptions) (*DefaultDialer, error) {
	var dialer net.Dialer
	var listener net.ListenConfig
	if options.BindInterface != "" {
		var interfaceFinder control.InterfaceFinder
		if router != nil {
			interfaceFinder = router.InterfaceFinder()
		} else {
			interfaceFinder = control.NewDefaultInterfaceFinder()
		}
		bindFunc := control.BindToInterface(interfaceFinder, options.BindInterface, -1)
		dialer.Control = control.Append(dialer.Control, bindFunc)
		listener.Control = control.Append(listener.Control, bindFunc)
	} else if router != nil && router.AutoDetectInterface() {
		bindFunc := router.AutoDetectInterfaceFunc()
		dialer.Control = control.Append(dialer.Control, bindFunc)
		listener.Control = control.Append(listener.Control, bindFunc)
	} else if router != nil && router.DefaultInterface() != "" {
		bindFunc := control.BindToInterface(router.InterfaceFinder(), router.DefaultInterface(), -1)
		dialer.Control = control.Append(dialer.Control, bindFunc)
		listener.Control = control.Append(listener.Control, bindFunc)
	}
	if options.RoutingMark != 0 {
		dialer.Control = control.Append(dialer.Control, control.RoutingMark(options.RoutingMark))
		listener.Control = control.Append(listener.Control, control.RoutingMark(options.RoutingMark))
	} else if router != nil && router.DefaultMark() != 0 {
		dialer.Control = control.Append(dialer.Control, control.RoutingMark(router.DefaultMark()))
		listener.Control = control.Append(listener.Control, control.RoutingMark(router.DefaultMark()))
	}
	if options.ReuseAddr {
		listener.Control = control.Append(listener.Control, control.ReuseAddr())
	}
	if options.ProtectPath != "" {
		dialer.Control = control.Append(dialer.Control, control.ProtectPath(options.ProtectPath))
		listener.Control = control.Append(listener.Control, control.ProtectPath(options.ProtectPath))
	}
	if options.ConnectTimeout != 0 {
		dialer.Timeout = time.Duration(options.ConnectTimeout)
	} else {
		dialer.Timeout = C.TCPTimeout
	}
	// TODO: Add an option to customize the keep alive period
	dialer.KeepAlive = C.TCPKeepAliveInitial
	dialer.Control = control.Append(dialer.Control, control.SetKeepAlivePeriod(C.TCPKeepAliveInitial, C.TCPKeepAliveInterval))
	var udpFragment bool
	if options.UDPFragment != nil {
		udpFragment = *options.UDPFragment
	} else {
		udpFragment = options.UDPFragmentDefault
	}
	if !udpFragment {
		dialer.Control = control.Append(dialer.Control, control.DisableUDPFragment())
		listener.Control = control.Append(listener.Control, control.DisableUDPFragment())
	}
	var (
		dialer4    = dialer
		udpDialer4 = dialer
		udpAddr4   string
	)
	if options.Inet4BindAddress != nil {
		bindAddr := options.Inet4BindAddress.Build()
		dialer4.LocalAddr = &net.TCPAddr{IP: bindAddr.AsSlice()}
		udpDialer4.LocalAddr = &net.UDPAddr{IP: bindAddr.AsSlice()}
		udpAddr4 = M.SocksaddrFrom(bindAddr, 0).String()
	}
	var (
		dialer6    = dialer
		udpDialer6 = dialer
		udpAddr6   string
	)
	if options.Inet6BindAddress != nil {
		bindAddr := options.Inet6BindAddress.Build()
		dialer6.LocalAddr = &net.TCPAddr{IP: bindAddr.AsSlice()}
		udpDialer6.LocalAddr = &net.UDPAddr{IP: bindAddr.AsSlice()}
		udpAddr6 = M.SocksaddrFrom(bindAddr, 0).String()
	}
	if options.TCPMultiPath {
		if !go121Available {
			return nil, E.New("MultiPath TCP requires go1.21, please recompile your binary.")
		}
		setMultiPathTCP(&dialer4)
	}
	if options.IsWireGuardListener {
		for _, controlFn := range wgControlFns {
			listener.Control = control.Append(listener.Control, controlFn)
		}
	}
	tcpDialer4, err := newTCPDialer(dialer4, options.TCPFastOpen)
	if err != nil {
		return nil, err
	}
	tcpDialer6, err := newTCPDialer(dialer6, options.TCPFastOpen)
	if err != nil {
		return nil, err
	}
	return &DefaultDialer{
		tcpDialer4,
		tcpDialer6,
		udpDialer4,
		udpDialer6,
		listener,
		udpAddr4,
		udpAddr6,
		options.IsWireGuardListener,
	}, nil
}

func dialContextWithRetry(dialer net.Dialer, ctx context.Context, network string, destination string) (net.Conn, error) {
	var err error
	for i := 0; i < 4; i++ {
		var conn net.Conn
		conn, err = dialer.DialContext(ctx, network, destination)
		if err == nil {
			return conn, nil
		}
	}
	return nil, err
}

type ConnWithErr struct {
	conn net.Conn
	err  error
}

func getResultFromConnChan(connChan chan ConnWithErr) (net.Conn, error) {
	var i int
	var err error
	defer func() {
		go func(index int) {
			for i := index; i < 3; i++ {
				if conn := <-connChan; conn.err == nil {
					go conn.conn.Close()
				}
			}
			close(connChan)
		}(i + 1)
	}()
	for i = 0; i < 3; i++ {
		conn := <-connChan
		if conn.err == nil {
			return conn.conn, nil
		}
		err = conn.err
	}
	return nil, err
}

func dialContextConcurrently(dialer net.Dialer, ctx context.Context, network string, destination string) (net.Conn, error) {
	if !ConcurrentDial {
		return dialContextWithRetry(dialer, ctx, network, destination)
	}
	connChan := make(chan ConnWithErr, 3)
	for i := 0; i < 3; i++ {
		go func() {
			var conn ConnWithErr
			conn.conn, conn.err = dialContextWithRetry(dialer, ctx, network, destination)
			connChan <- conn
		}()
	}
	return getResultFromConnChan(connChan)
}

func (d *DefaultDialer) DialContext(ctx context.Context, network string, address M.Socksaddr) (net.Conn, error) {
	if !address.IsValid() {
		return nil, E.New("invalid address")
	}
	if N.NetworkName(network) == N.NetworkUDP {
		if !address.IsIPv6() {
			return dialContextConcurrently(d.udpDialer4, ctx, network, address.String())
		}
		return dialContextConcurrently(d.udpDialer6, ctx, network, address.String())
	} else if !address.IsIPv6() {
		return trackConn(DialSlowContext(&d.dialer4, ctx, network, address))
	}
	return trackConn(DialSlowContext(&d.dialer6, ctx, network, address))
}

func listenPacketWithRetry(listener net.ListenConfig, ctx context.Context, network string, address string) (net.PacketConn, error) {
	var err error
	for i := 0; i < 4; i++ {
		var conn net.PacketConn
		conn, err = listener.ListenPacket(ctx, network, address)
		if err == nil {
			return conn, nil
		}
	}
	return nil, err
}

type PacketConnWithErr struct {
	conn net.PacketConn
	err  error
}

func getResultFromPacketConnChan(connChan chan PacketConnWithErr) (net.PacketConn, error) {
	var i int
	var err error
	defer func() {
		go func(index int) {
			for i := index; i < 3; i++ {
				if packet := <-connChan; packet.err == nil {
					go packet.conn.Close()
				}
			}
			close(connChan)
		}(i + 1)
	}()
	for i = 0; i < 3; i++ {
		packet := <-connChan
		if packet.err == nil {
			return packet.conn, nil
		}
		err = packet.err
	}
	return nil, err
}

func listenPacketConcurrently(listener net.ListenConfig, ctx context.Context, network string, address string) (net.PacketConn, error) {
	if !ConcurrentDial {
		return listenPacketWithRetry(listener, ctx, network, address)
	}
	connChan := make(chan PacketConnWithErr, 3)
	for i := 0; i < 3; i++ {
		go func() {
			var packet PacketConnWithErr
			packet.conn, packet.err = listenPacketWithRetry(listener, ctx, network, address)
			connChan <- packet
		}()
	}
	return getResultFromPacketConnChan(connChan)
}

func (d *DefaultDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if destination.IsIPv6() {
		return trackPacketConn(listenPacketConcurrently(d.udpListener, ctx, N.NetworkUDP, d.udpAddr6))
	} else if destination.IsIPv4() && !destination.Addr.IsUnspecified() {
		return trackPacketConn(listenPacketConcurrently(d.udpListener, ctx, N.NetworkUDP+"4", d.udpAddr4))
	} else {
		return trackPacketConn(listenPacketConcurrently(d.udpListener, ctx, N.NetworkUDP, d.udpAddr4))
	}
}

func (d *DefaultDialer) ListenPacketCompat(network, address string) (net.PacketConn, error) {
	return trackPacketConn(d.udpListener.ListenPacket(context.Background(), network, address))
}

func trackConn(conn net.Conn, err error) (net.Conn, error) {
	if !conntrack.Enabled || err != nil {
		return conn, err
	}
	return conntrack.NewConn(conn)
}

func trackPacketConn(conn net.PacketConn, err error) (net.PacketConn, error) {
	if !conntrack.Enabled || err != nil {
		return conn, err
	}
	return conntrack.NewPacketConn(conn)
}
