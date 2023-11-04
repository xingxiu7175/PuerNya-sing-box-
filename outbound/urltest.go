package outbound

import (
	"context"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/batch"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

var (
	_ adapter.Outbound                = (*URLTest)(nil)
	_ adapter.OutboundGroup           = (*URLTest)(nil)
	_ adapter.InterfaceUpdateListener = (*URLTest)(nil)
)

type URLTest struct {
	myOutboundAdapter
	myGroupAdapter
	ctx                          context.Context
	link                         string
	interval                     time.Duration
	tolerance                    uint16
	group                        *URLTestGroup
	interruptExternalConnections bool
}

func NewURLTest(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.URLTestOutboundOptions) (*URLTest, error) {
	outbound := &URLTest{
		myOutboundAdapter: myOutboundAdapter{
			protocol:     C.TypeURLTest,
			router:       router,
			logger:       logger,
			tag:          tag,
			dependencies: options.Outbounds,
		},
		myGroupAdapter: myGroupAdapter{
			tags:      options.Outbounds,
			uses:      options.Providers,
			includes:  options.Includes,
			excludes:  options.Excludes,
			types:     options.Types,
			ports:     make(map[int]bool),
			providers: make(map[string]adapter.OutboundProvider),
		},
		ctx:                          ctx,
		link:                         options.URL,
		interval:                     time.Duration(options.Interval),
		tolerance:                    options.Tolerance,
		interruptExternalConnections: options.InterruptExistConnections,
	}
	if len(outbound.tags) == 0 && len(outbound.uses) == 0 {
		return nil, E.New("missing tags and uses")
	}
	portMap, err := CreatePortsMap(options.Ports)
	if err != nil {
		return nil, err
	}
	outbound.ports = portMap
	return outbound, nil
}

func (s *URLTest) Network() []string {
	s.group.RLock()
	defer s.group.RUnlock()
	if s.group == nil {
		return []string{N.NetworkTCP, N.NetworkUDP}
	}
	s.group.RLock()
	defer s.group.RUnlock()
	return s.group.Select(N.NetworkTCP).Network()
}

func (s *URLTest) PickOutbounds() ([]adapter.Outbound, error) {
	outbounds := []adapter.Outbound{}
	for i, tag := range s.tags {
		detour, loaded := s.router.Outbound(tag)
		if !loaded {
			return nil, E.New("outbound ", i, " not found: ", tag)
		}
		outbounds = append(outbounds, detour)
	}
	for i, tag := range s.uses {
		provider, loaded := s.router.OutboundProvider(tag)
		if !loaded {
			return nil, E.New("provider ", i, " not found: ", tag)
		}
		if _, ok := s.providers[tag]; !ok {
			s.providers[tag] = provider
		}
		for _, outbound := range provider.Outbounds() {
			if s.OutboundFilter(outbound) {
				outbounds = append(outbounds, outbound)
			}
		}
	}
	if len(outbounds) == 0 {
		OUTBOUNDLESS, _ := s.router.Outbound("OUTBOUNDLESS")
		outbounds = append(outbounds, OUTBOUNDLESS)
	}
	return outbounds, nil
}

func (s *URLTest) Start() error {
	outbounds, err := s.PickOutbounds()
	if err != nil {
		return err
	}
	s.group = NewURLTestGroup(s.ctx, s.router, s.logger, outbounds, s.link, s.interval, s.tolerance, s.interruptExternalConnections)
	return nil
}

func (s *URLTest) UpdateOutbounds(tag string) error {
	if _, ok := s.providers[tag]; ok {
		s.group.RLock()
		outbounds, err := s.PickOutbounds()
		if err != nil {
			s.group.RUnlock()
			return E.New("update outbounds failed: ", s.tag, ", with reason: ", err)
		}
		s.group.outbounds = outbounds
		s.group.RUnlock()
		s.group.performUpdateCheck()
	}
	return nil
}

func (s *URLTest) PostStart() error {
	go s.CheckOutbounds()
	return nil
}

func (s *URLTest) Close() error {
	return common.Close(
		common.PtrOrNil(s.group),
	)
}

func (s *URLTest) Now() string {
	s.group.RLock()
	defer s.group.RUnlock()
	return s.group.Select(N.NetworkTCP).Tag()
}

func (s *URLTest) SelectedOutbound(network string) adapter.Outbound {
	s.group.RLock()
	defer s.group.RUnlock()
	return s.group.Select(network)
}

func (s *URLTest) All() []string {
	s.group.RLock()
	defer s.group.RUnlock()
	all := []string{}
	for _, outbound := range s.group.outbounds {
		all = append(all, outbound.Tag())
	}
	return all
}

func (s *URLTest) URLTest(ctx context.Context, link string) (map[string]uint16, error) {
	s.group.RLock()
	defer s.group.RUnlock()
	return s.group.URLTest(ctx, link)
}

func (s *URLTest) CheckOutbounds() {
	s.group.RLock()
	defer s.group.RUnlock()
	s.group.CheckOutbounds(true)
}

func (s *URLTest) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	s.group.RLock()
	s.group.RUnlock()
	s.group.Start()
	outbound := s.group.Select(network)
	conn, err := outbound.DialContext(ctx, network, destination)
	if err == nil {
		return s.group.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
	}
	s.logger.ErrorContext(ctx, err)
	s.group.history.DeleteURLTestHistory(outbound.Tag())
	return nil, err
}

func (s *URLTest) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	s.group.RLock()
	s.group.RUnlock()
	s.group.Start()
	outbound := s.group.Select(N.NetworkUDP)
	conn, err := outbound.ListenPacket(ctx, destination)
	if err == nil {
		return s.group.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
	}
	s.logger.ErrorContext(ctx, err)
	s.group.history.DeleteURLTestHistory(outbound.Tag())
	return nil, err
}

func (s *URLTest) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	return NewConnection(ctx, s, conn, metadata)
}

func (s *URLTest) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	return NewPacketConnection(ctx, s, conn, metadata)
}

func (s *URLTest) InterfaceUpdated() {
	go s.group.CheckOutbounds(true)
	return
}

type URLTestGroup struct {
	ctx                          context.Context
	router                       adapter.Router
	logger                       log.Logger
	outbounds                    []adapter.Outbound
	link                         string
	interval                     time.Duration
	tolerance                    uint16
	history                      *urltest.HistoryStorage
	checking                     atomic.Bool
	pauseManager                 pause.Manager
	selectedOutboundTCP          adapter.Outbound
	selectedOutboundUDP          adapter.Outbound
	interruptGroup               *interrupt.Group
	interruptExternalConnections bool

	sync.RWMutex
	access sync.Mutex
	ticker *time.Ticker
	close  chan struct{}
}

func NewURLTestGroup(
	ctx context.Context,
	router adapter.Router,
	logger log.Logger,
	outbounds []adapter.Outbound,
	link string,
	interval time.Duration,
	tolerance uint16,
	interruptExternalConnections bool,
) *URLTestGroup {
	if interval == 0 {
		interval = C.DefaultURLTestInterval
	}
	if tolerance == 0 {
		tolerance = 50
	}
	var history *urltest.HistoryStorage
	if history = service.PtrFromContext[urltest.HistoryStorage](ctx); history != nil {
	} else if clashServer := router.ClashServer(); clashServer != nil {
		history = clashServer.HistoryStorage()
	} else {
		history = urltest.NewHistoryStorage()
	}
	return &URLTestGroup{
		ctx:                          ctx,
		router:                       router,
		logger:                       logger,
		outbounds:                    outbounds,
		link:                         link,
		interval:                     interval,
		tolerance:                    tolerance,
		history:                      history,
		close:                        make(chan struct{}),
		pauseManager:                 pause.ManagerFromContext(ctx),
		interruptGroup:               interrupt.NewGroup(),
		interruptExternalConnections: interruptExternalConnections,
	}
}

func (g *URLTestGroup) Start() {
	if g.ticker != nil {
		return
	}
	g.access.Lock()
	defer g.access.Unlock()
	if g.ticker != nil {
		return
	}
	g.ticker = time.NewTicker(g.interval)
	go g.loopCheck()
}

func (g *URLTestGroup) Close() error {
	if g.ticker == nil {
		return nil
	}
	g.ticker.Stop()
	close(g.close)
	return nil
}

func (g *URLTestGroup) Select(network string) adapter.Outbound {
	g.RLock()
	g.RUnlock()
	var minDelay uint16
	var minTime time.Time
	minOutbound := g.outbounds[0]
	for _, detour := range g.outbounds {
		if !common.Contains(detour.Network(), network) {
			continue
		}
		history := g.history.LoadURLTestHistory(RealTag(detour))
		if history == nil {
			continue
		}
		if minDelay == 0 || minDelay > history.Delay+g.tolerance || minDelay > history.Delay-g.tolerance && minTime.Before(history.Time) {
			minDelay = history.Delay
			minTime = history.Time
			minOutbound = detour
		}
	}
	if minOutbound == nil {
		for _, detour := range g.outbounds {
			if !common.Contains(detour.Network(), network) {
				continue
			}
			minOutbound = detour
			break
		}
	}
	return minOutbound
}

func (g *URLTestGroup) Fallback(used adapter.Outbound) []adapter.Outbound {
	g.RLock()
	g.RUnlock()
	outbounds := make([]adapter.Outbound, 0, len(g.outbounds)-1)
	for _, detour := range g.outbounds {
		if detour != used {
			outbounds = append(outbounds, detour)
		}
	}
	sort.SliceStable(outbounds, func(i, j int) bool {
		oi := outbounds[i]
		oj := outbounds[j]
		hi := g.history.LoadURLTestHistory(RealTag(oi))
		if hi == nil {
			return false
		}
		hj := g.history.LoadURLTestHistory(RealTag(oj))
		if hj == nil {
			return false
		}
		return hi.Delay < hj.Delay
	})
	return outbounds
}

func (g *URLTestGroup) loopCheck() {
	go g.CheckOutbounds(true)
	for {
		g.pauseManager.WaitActive()
		select {
		case <-g.close:
			return
		case <-g.ticker.C:
			g.CheckOutbounds(false)
		}
	}
}

func (g *URLTestGroup) CheckOutbounds(force bool) {
	_, _ = g.urlTest(g.ctx, g.link, force)
}

func (g *URLTestGroup) URLTest(ctx context.Context, link string) (map[string]uint16, error) {
	return g.urlTest(ctx, link, false)
}

func (g *URLTestGroup) urlTest(ctx context.Context, link string, force bool) (map[string]uint16, error) {
	g.RLock()
	g.RUnlock()
	result := make(map[string]uint16)
	if g.checking.Swap(true) {
		return result, nil
	}
	defer g.checking.Store(false)
	b, _ := batch.New(ctx, batch.WithConcurrencyNum[any](10))
	checked := make(map[string]bool)
	var resultAccess sync.Mutex
	for _, detour := range g.outbounds {
		tag := detour.Tag()
		realTag := RealTag(detour)
		if checked[realTag] {
			continue
		}
		history := g.history.LoadURLTestHistory(realTag)
		if !force && history != nil && time.Now().Sub(history.Time) < g.interval {
			continue
		}
		checked[realTag] = true
		p, loaded := g.router.OutboundWithProvider(realTag)
		if !loaded {
			continue
		}
		b.Go(realTag, func() (any, error) {
			ctx, cancel := context.WithTimeout(context.Background(), C.TCPTimeout)
			defer cancel()
			t, err := urltest.URLTest(ctx, link, p)
			if err != nil {
				g.logger.Debug("outbound ", tag, " unavailable: ", err)
				g.history.DeleteURLTestHistory(realTag)
			} else {
				g.logger.Debug("outbound ", tag, " available: ", t, "ms")
				g.history.StoreURLTestHistory(realTag, &urltest.History{
					Time:  time.Now(),
					Delay: t,
				})
				resultAccess.Lock()
				result[tag] = t
				resultAccess.Unlock()
			}
			return nil, nil
		})
	}
	b.Wait()
	g.performUpdateCheck()
	return result, nil
}

func (g *URLTestGroup) performUpdateCheck() {
	outbound := g.Select(N.NetworkTCP)
	var updated bool
	if outbound != g.selectedOutboundTCP {
		g.selectedOutboundTCP = outbound
		updated = true
	}
	outbound = g.Select(N.NetworkUDP)
	if outbound != g.selectedOutboundUDP {
		g.selectedOutboundUDP = outbound
		updated = true
	}
	if updated {
		g.interruptGroup.Interrupt(g.interruptExternalConnections)
	}
}
