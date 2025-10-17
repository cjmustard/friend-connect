package session

import "github.com/cjmustard/consoleconnect/broadcast/constants"

// HandleRequest mirrors the Xbox session handle payload structure.
type HandleRequest struct {
	Version          int               `json:"version"`
	Type             string            `json:"type"`
	SessionRef       SessionRef        `json:"sessionRef"`
	InvitedXUID      string            `json:"invitedXuid,omitempty"`
	InviteAttributes map[string]string `json:"inviteAttributes,omitempty"`
}

// SessionRef identifies a multiplayer session handle target.
type SessionRef struct {
	SCID         string `json:"scid"`
	TemplateName string `json:"templateName"`
	Name         string `json:"name"`
}

// NewSessionRef constructs a reference for the provided session identifier.
func NewSessionRef(sessionID string) SessionRef {
	return SessionRef{
		SCID:         constants.ServiceConfigID,
		TemplateName: constants.TemplateName,
		Name:         sessionID,
	}
}

// NewActivityHandle builds the payload required to register an activity handle.
func NewActivityHandle(sessionID string) HandleRequest {
	return HandleRequest{
		Version:    1,
		Type:       "activity",
		SessionRef: NewSessionRef(sessionID),
	}
}

// NewInviteHandle builds the payload for an invite handle targeting the supplied XUID.
func NewInviteHandle(sessionID, xuid, titleID string) HandleRequest {
	attrs := map[string]string{}
	if titleID != "" {
		attrs["titleId"] = titleID
	}
	return HandleRequest{
		Version:          1,
		Type:             "invite",
		SessionRef:       NewSessionRef(sessionID),
		InvitedXUID:      xuid,
		InviteAttributes: attrs,
	}
}
