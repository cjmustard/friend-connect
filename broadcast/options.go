package broadcast

import "time"

type Options struct {
	Accounts []AccountOptions
	Friends  FriendOptions
	Listener ListenerOptions
	Relay    RelayOptions
}

type AccountOptions struct {
	Gamertag     string
	RefreshToken string
	ShowAsOnline bool
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
