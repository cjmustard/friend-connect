package session

import "math/big"

type createSessionRequest struct {
	Members    map[string]sessionMember `json:"members"`
	Properties sessionProperties        `json:"properties"`
}

type sessionMember struct {
	JoinTime   *string                           `json:"joinTime,omitempty"`
	Constants  map[string]memberConstantsSystem  `json:"constants"`
	Gamertag   string                            `json:"gamertag,omitempty"`
	Properties map[string]memberPropertiesSystem `json:"properties"`
}

type memberConstantsSystem struct {
	XUID       string `json:"xuid"`
	Initialize bool   `json:"initialize"`
}

type memberPropertiesSystem struct {
	Active       bool               `json:"active"`
	Connection   string             `json:"connection"`
	Subscription memberSubscription `json:"subscription"`
}

type memberSubscription struct {
	ID          string   `json:"id"`
	ChangeTypes []string `json:"changeTypes"`
}

type sessionProperties struct {
	System sessionSystemProperties `json:"system"`
	Custom sessionCustomProperties `json:"custom"`
}

type sessionSystemProperties struct {
	JoinRestriction string `json:"joinRestriction"`
	ReadRestriction string `json:"readRestriction"`
	Closed          bool   `json:"closed"`
}

type sessionCustomProperties struct {
	BroadcastSetting        int                 `json:"BroadcastSetting"`
	CrossPlayDisabled       bool                `json:"CrossPlayDisabled"`
	Joinability             string              `json:"Joinability"`
	LanGame                 bool                `json:"LanGame"`
	MaxMemberCount          int                 `json:"MaxMemberCount"`
	MemberCount             int                 `json:"MemberCount"`
	OnlineCrossPlatformGame bool                `json:"OnlineCrossPlatformGame"`
	SupportedConnections    []sessionConnection `json:"SupportedConnections"`
	TitleID                 int                 `json:"TitleId"`
	TransportLayer          int                 `json:"TransportLayer"`
	LevelID                 string              `json:"levelId"`
	HostName                string              `json:"hostName"`
	OwnerID                 string              `json:"ownerId"`
	RakNetGUID              string              `json:"rakNetGUID"`
	WorldName               string              `json:"worldName"`
	WorldType               string              `json:"worldType"`
	Protocol                int                 `json:"protocol"`
	Version                 string              `json:"version"`
	IsEditorWorld           bool                `json:"isEditorWorld"`
	IsHardcore              bool                `json:"isHardcore"`
}

type sessionConnection struct {
	ConnectionType int         `json:"ConnectionType"`
	HostIPAddress  string      `json:"HostIpAddress"`
	HostPort       int         `json:"HostPort"`
	NetherNetID    netherNetID `json:"NetherNetId"`
}

type netherNetID struct {
	*big.Int
}

func (n netherNetID) MarshalJSON() ([]byte, error) {
	if n.Int == nil {
		return []byte("0"), nil
	}
	return []byte(n.String()), nil
}
