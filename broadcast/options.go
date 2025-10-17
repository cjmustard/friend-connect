package broadcast

import (
	"time"

	"github.com/cjmustard/consoleconnect/broadcast/logger"
	"golang.org/x/oauth2"
)

type Options struct {
	Tokens   []*oauth2.Token
	Friends  FriendOptions
	Listener ListenerOptions
	Relay    RelayOptions
	Logger   *logger.Logger
}

type FriendOptions struct {
	AutoAccept bool
	AutoAdd    bool
	SyncTicker time.Duration
}

type ListenerOptions struct {
	Address string
	Name    string
	Message string
}

type RelayOptions struct {
	RemoteAddress string
	VerifyTarget  bool
	Timeout       time.Duration
}

func (o *Options) ApplyDefaults() {
	if o.Friends.SyncTicker <= 0 {
		o.Friends.SyncTicker = time.Minute
	}
	if o.Listener.Address == "" {
		o.Listener.Address = "0.0.0.0:19132"
	}
	if o.Listener.Name == "" {
		o.Listener.Name = "Console Connect"
	}
	if o.Listener.Message == "" {
		o.Listener.Message = "Minecraft Presence Relay"
	}
	if o.Relay.Timeout <= 0 {
		o.Relay.Timeout = 5 * time.Second
	}
	if o.Relay.RemoteAddress != "" && !o.Relay.VerifyTarget {
		o.Relay.VerifyTarget = true
	}
}

type OptionsProvider interface {
	Options() Options
}
