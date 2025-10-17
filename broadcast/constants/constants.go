package constants

import "time"

const (
	ServiceConfigID = "4fc10100-5f7a-4470-899b-280835760c07"
	TemplateName    = "MinecraftLobby"
	TitleID         = "896928775"
	PlayfabLoginURL = "https://20ca2.playfabapi.com/Client/LoginWithXbox"

	RelyingPartyXboxLive    = "http://xboxlive.com"
	RelyingPartyMultiplayer = "https://multiplayer.minecraft.net/"
	RelyingPartyPlayFab     = "https://b980a380.minecraft.playfabapi.com/"
)

var (
	RtaWebsocketURL      = "wss://rta.xboxlive.com/connect"
	FollowersURL         = "https://peoplehub.xboxlive.com/users/me/people/followers"
	SocialURL            = "https://peoplehub.xboxlive.com/users/me/people/social"
	SocialSummaryURL     = "https://social.xboxlive.com/users/me/summary"
	WebsocketDialTimeout = 10 * time.Second
	ConnectionTypeWebRTC = 3
	MaxFriends           = 2000
)

func PeopleURL(xuid string) string {
	return "https://social.xboxlive.com/users/me/people/xuid(" + xuid + ")"
}

func UserPresenceURL(xuid string) string {
	return "https://userpresence.xboxlive.com/users/xuid(" + xuid + ")/devices/current/titles/current"
}

func ProfileSettingsURL(xuid string) string {
	return "https://profile.xboxlive.com/users/xuid(" + xuid + ")/profile/settings?settings=Gamertag"
}

func FollowerURL(xuid string) string {
	return "https://social.xboxlive.com/users/me/people/follower/xuid(" + xuid + ")"
}
