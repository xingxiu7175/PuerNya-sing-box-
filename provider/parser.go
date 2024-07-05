package provider

import (
	"reflect"
	"strings"

	"github.com/sagernet/sing-box/common/betterjson"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

func (p *myProviderAdapter) newParser(content string) ([]option.Outbound, error) {
	var outbounds []option.Outbound
	var err error
	switch true {
	case strings.Contains(content, "outbounds"):
		var options option.OutboundProviderOptions
		if parsedContent, err := betterjson.PreConvert([]byte(content)); err != nil {
			return nil, E.Cause(err, "decode config at ")
		} else if err := options.UnmarshalJSON(parsedContent); err != nil {
			return nil, E.Cause(err, "decode config at ")
		}
		outbounds = options.Outbounds
	case strings.Contains(content, "proxies"):
		outbounds, err = newClashParser(content)
		if err != nil {
			return nil, err
		}
	default:
		outbounds, err = newNativeURIParser(content)
		if err != nil {
			return nil, err
		}
	}
	return p.overrideOutbounds(outbounds), nil
}

func (p *myProviderAdapter) overrideOutbounds(outbounds []option.Outbound) []option.Outbound {
	var tags []string
	for _, outbound := range outbounds {
		tags = append(tags, outbound.Tag)
	}
	var parsedOutbounds []option.Outbound
	for _, outbound := range outbounds {
		switch outbound.Type {
		case C.TypeHTTP:
			dialer := outbound.HTTPOptions.DialerOptions
			outbound.HTTPOptions.DialerOptions = p.overrideDialerOption(dialer, tags)
		case C.TypeSOCKS:
			dialer := outbound.SocksOptions.DialerOptions
			outbound.SocksOptions.DialerOptions = p.overrideDialerOption(dialer, tags)
		case C.TypeTUIC:
			dialer := outbound.TUICOptions.DialerOptions
			outbound.TUICOptions.DialerOptions = p.overrideDialerOption(dialer, tags)
		case C.TypeVMess:
			dialer := outbound.VMessOptions.DialerOptions
			outbound.VMessOptions.DialerOptions = p.overrideDialerOption(dialer, tags)
		case C.TypeVLESS:
			dialer := outbound.VLESSOptions.DialerOptions
			outbound.VLESSOptions.DialerOptions = p.overrideDialerOption(dialer, tags)
		case C.TypeTrojan:
			dialer := outbound.TrojanOptions.DialerOptions
			outbound.TrojanOptions.DialerOptions = p.overrideDialerOption(dialer, tags)
		case C.TypeHysteria:
			dialer := outbound.HysteriaOptions.DialerOptions
			outbound.HysteriaOptions.DialerOptions = p.overrideDialerOption(dialer, tags)
		case C.TypeShadowTLS:
			dialer := outbound.ShadowTLSOptions.DialerOptions
			outbound.ShadowTLSOptions.DialerOptions = p.overrideDialerOption(dialer, tags)
		case C.TypeHysteria2:
			dialer := outbound.Hysteria2Options.DialerOptions
			outbound.Hysteria2Options.DialerOptions = p.overrideDialerOption(dialer, tags)
		case C.TypeWireGuard:
			dialer := outbound.WireGuardOptions.DialerOptions
			outbound.WireGuardOptions.DialerOptions = p.overrideDialerOption(dialer, tags)
		case C.TypeShadowsocks:
			dialer := outbound.ShadowsocksOptions.DialerOptions
			outbound.ShadowsocksOptions.DialerOptions = p.overrideDialerOption(dialer, tags)
		case C.TypeShadowsocksR:
			dialer := outbound.ShadowsocksROptions.DialerOptions
			outbound.ShadowsocksROptions.DialerOptions = p.overrideDialerOption(dialer, tags)
		}
		parsedOutbounds = append(parsedOutbounds, outbound)
	}
	return parsedOutbounds
}

func (p *myProviderAdapter) overrideDialerOption(options option.DialerOptions, tags []string) option.DialerOptions {
	if options.Detour != "" && !common.Any(tags, func(tag string) bool {
		return options.Detour == tag
	}) {
		options.Detour = ""
	}
	var defaultOptions option.OverrideDialerOptions
	if p.overrideDialer == nil || reflect.DeepEqual(*p.overrideDialer, defaultOptions) {
		return options
	}
	if p.overrideDialer.Detour != nil && options.Detour == "" {
		options.Detour = *p.overrideDialer.Detour
	}
	if p.overrideDialer.BindInterface != nil {
		options.BindInterface = *p.overrideDialer.BindInterface
	}
	if p.overrideDialer.Inet4BindAddress != nil {
		options.Inet4BindAddress = p.overrideDialer.Inet4BindAddress
	}
	if p.overrideDialer.Inet6BindAddress != nil {
		options.Inet6BindAddress = p.overrideDialer.Inet6BindAddress
	}
	if p.overrideDialer.ProtectPath != nil {
		options.ProtectPath = *p.overrideDialer.ProtectPath
	}
	if p.overrideDialer.RoutingMark != nil {
		options.RoutingMark = *p.overrideDialer.RoutingMark
	}
	if p.overrideDialer.ReuseAddr != nil {
		options.ReuseAddr = *p.overrideDialer.ReuseAddr
	}
	if p.overrideDialer.ConnectTimeout != nil {
		options.ConnectTimeout = *p.overrideDialer.ConnectTimeout
	}
	if p.overrideDialer.TCPFastOpen != nil {
		options.TCPFastOpen = *p.overrideDialer.TCPFastOpen
	}
	if p.overrideDialer.TCPMultiPath != nil {
		options.TCPMultiPath = *p.overrideDialer.TCPMultiPath
	}
	if p.overrideDialer.UDPFragment != nil {
		options.UDPFragment = p.overrideDialer.UDPFragment
	}
	if p.overrideDialer.DomainStrategy != nil {
		options.UDPFragment = p.overrideDialer.UDPFragment
	}
	if p.overrideDialer.FallbackDelay != nil {
		options.FallbackDelay = *p.overrideDialer.FallbackDelay
	}
	if p.overrideDialer.StoreLastIP != nil {
		options.StoreLastIP = *p.overrideDialer.StoreLastIP
	}
	return options
}
