package broadcast

import (
	"time"

	"github.com/cjmustard/consoleconnect/broadcast/notifications"
)

type Options struct {
	XboxClientID     string               `json:"xboxClientId,omitempty"`
	XboxClientSecret string               `json:"xboxClientSecret,omitempty"`
	Accounts         []AccountOptions     `json:"accounts,omitempty"`
	Storage          StorageOptions       `json:"storage"`
	Friends          FriendOptions        `json:"friends"`
	Invite           InviteOptions        `json:"invite"`
	HTTP             HTTPOptions          `json:"http"`
	Ping             PingOptions          `json:"ping"`
	Gallery          GalleryOptions       `json:"gallery"`
	Notifications    notifications.Config `json:"notifications"`
	CustomImages     map[string]string    `json:"customImages,omitempty"`
	Listener         ListenerOptions      `json:"listener"`
}

type AccountOptions struct {
	Gamertag     string   `json:"gamertag"`
	RefreshToken string   `json:"refreshToken"`
	ShowAsOnline bool     `json:"showAsOnline"`
	PreferredIPs []string `json:"preferredIps,omitempty"`
}

type StorageOptions struct {
	Directory string `json:"directory"`
}

type FriendOptions struct {
	AutoAccept bool          `json:"autoAccept"`
	AutoAdd    bool          `json:"autoAdd"`
	SyncTicker time.Duration `json:"syncTicker"`
}

type InviteOptions struct {
	Enabled  bool          `json:"enabled"`
	Interval time.Duration `json:"interval"`
}

type HTTPOptions struct {
	Addr         string        `json:"addr"`
	ReadTimeout  time.Duration `json:"readTimeout"`
	WriteTimeout time.Duration `json:"writeTimeout"`
}

type PingOptions struct {
	Enabled bool          `json:"enabled"`
	Target  string        `json:"target"`
	Period  time.Duration `json:"period"`
}

type GalleryOptions struct {
	Enabled bool   `json:"enabled"`
	Path    string `json:"path"`
}

type ListenerOptions struct {
	Address string `json:"address"`
	Name    string `json:"name"`
	Message string `json:"message"`
}

func (o *Options) ApplyDefaults() {
	if o.HTTP.Addr == "" {
		o.HTTP.Addr = ":8080"
	}
	if o.HTTP.ReadTimeout == 0 {
		o.HTTP.ReadTimeout = 5 * time.Second
	}
	if o.HTTP.WriteTimeout == 0 {
		o.HTTP.WriteTimeout = 5 * time.Second
	}
	if o.Friends.SyncTicker == 0 {
		o.Friends.SyncTicker = time.Minute
	}
	if o.Invite.Interval == 0 {
		o.Invite.Interval = time.Minute
	}
	if o.Ping.Period == 0 {
		o.Ping.Period = 30 * time.Second
	}
	if o.Gallery.Path == "" {
		o.Gallery.Path = "gallery"
	}
	if o.Listener.Address == "" {
		o.Listener.Address = "0.0.0.0:19132"
	}
	if o.Listener.Name == "" {
		o.Listener.Name = "Broadcaster"
	}
	if o.Listener.Message == "" {
		o.Listener.Message = "Minecraft Presence Relay"
	}
	if o.CustomImages == nil {
		o.CustomImages = map[string]string{}
	}
	if o.Notifications.SessionExpiredMessage == "" {
		o.Notifications.SessionExpiredMessage = "Authenticate at %s using the code %s"
	}
	if o.Notifications.FriendRestrictionMessage == "" {
		o.Notifications.FriendRestrictionMessage = "Friend restriction detected for %s (%s)"
	}
}

type OptionsProvider interface {
	Options() Options
}
