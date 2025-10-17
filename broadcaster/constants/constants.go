package constants

import "time"

const (
	ServiceConfigID  = "4fc10100-5f7a-4470-899b-280835760c07"
	TemplateName     = "MinecraftLobby"
	TitleID          = "896928775"
	CreateSessionURL = "https://sessiondirectory.xboxlive.com/serviceconfigs/" + ServiceConfigID + "/sessionTemplates/" + TemplateName + "/sessions/%s"
	JoinSessionURL   = "https://sessiondirectory.xboxlive.com/handles/%s/session"
	PlayfabLoginURL  = "https://20ca2.playfabapi.com/Client/LoginWithXbox"
	RTCWebsocketURL  = "wss://signal.franchise.minecraft-services.net/ws/v1.0/signaling/%s"
)

var (
	StartSessionURL      = "https://authorization.franchise.minecraft-services.net/api/v1.0/session/start"
	RtaWebsocketURL      = "wss://rta.xboxlive.com/connect"
	CreateHandleURL      = "https://sessiondirectory.xboxlive.com/handles"
	FollowersURL         = "https://peoplehub.xboxlive.com/users/me/people/followers"
	SocialURL            = "https://peoplehub.xboxlive.com/users/me/people/social"
	SocialSummaryURL     = "https://social.xboxlive.com/users/me/summary"
	GalleryURL           = "https://persona.franchise.minecraft-services.net/api/v1.0/gallery"
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
