package main

import (
	"context"

	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/ccding/go-stun/stun"
	"github.com/spf13/cobra"
)

var commandSTUN = &cobra.Command{
	Use:   "stun",
	Short: "Test NAT type through stun",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		err := stunCaller(args)
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	commandTools.AddCommand(commandSTUN)
}

func multiCaller(dialer N.Dialer, addr metadata.Socksaddr) (stun.NATType, *stun.Host, error) {
	conn, err := dialer.ListenPacket(context.Background(), addr)
	if err != nil {
		return stun.NATError, nil, err
	}
	return stun.NewClientWithConnection(conn).Discover()
}

func stunCaller(args []string) error {
	if len(args) > 1 {
		return E.New("stun tool can only be used simply")
	}
	instance, err := createPreStartedClient()
	if err != nil {
		return err
	}
	defer instance.Close()
	dialer, err := createDialer(instance, N.NetworkUDP, commandToolsFlagOutbound)
	if err != nil {
		return err
	}
	rawAddr := metadata.ParseSocksaddr(args[0])
	if rawAddr.Port == 0 {
		rawAddr.Port = 3478
	}
	var nattype stun.NATType
	if !rawAddr.IsFqdn() {
		nattype, _, err = multiCaller(dialer, rawAddr)
	} else {
		addrs, err := instance.Router().LookupDefault(context.Background(), rawAddr.Fqdn)
		if err != nil {
			return err
		}
		for _, addr := range addrs {
			nattype, _, err = multiCaller(dialer, metadata.Socksaddr{
				Addr: addr,
				Port: rawAddr.Port,
			})
			if err != nil {
				continue
			}
			switch nattype {
			case stun.NATBlocked, stun.NATError, stun.NATNone, stun.NATUnknown:
				continue
			}
		}
	}
	if err != nil {
		return err
	}
	switch nattype {
	case stun.NATBlocked, stun.NATError, stun.NATNone, stun.NATUnknown:
		return E.New(nattype.String())
	}
	log.Info(nattype.String())
	return nil
}
