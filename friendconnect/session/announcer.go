package session

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/df-mc/go-xsapi"
	"github.com/df-mc/go-xsapi/mpsd"
	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/room"
)

type GalleryAnnouncer struct {
	TokenSource      xsapi.TokenSource
	SessionReference mpsd.SessionReference
	PublishConfig    mpsd.PublishConfig
	Session          *mpsd.Session

	gallery func() GalleryOptions

	custom []byte
	mu     sync.Mutex
}

func (a *GalleryAnnouncer) setGalleryProvider(provider func() GalleryOptions) {
	a.mu.Lock()
	a.gallery = provider
	a.mu.Unlock()
}

func (a *GalleryAnnouncer) Announce(ctx context.Context, status room.Status) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	payload := statusPayload{Status: status}
	if a.gallery != nil {
		if gallery := a.gallery().payload(); gallery != nil {
			payload.Gallery = gallery
			fmt.Printf("gallery: announcing session with %d gallery items\n", len(gallery.Items))
		} else {
			fmt.Printf("gallery: no gallery payload generated\n")
		}
	} else {
		fmt.Printf("gallery: no gallery provider set\n")
	}

	custom, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode: %w", err)
	}
	if bytes.Equal(custom, a.custom) {
		fmt.Printf("gallery: session data unchanged, skipping update\n")
		return nil
	}
	a.custom = custom

	// Log the first 200 characters of the custom data to see what's being sent
	customStr := string(custom)
	if len(customStr) > 200 {
		fmt.Printf("gallery: sending session data (first 200 chars): %s...\n", customStr[:200])
	} else {
		fmt.Printf("gallery: sending session data: %s\n", customStr)
	}

	if a.Session == nil {
		if a.PublishConfig.Description == nil {
			a.PublishConfig.Description = a.description(status, custom)
		} else {
			a.PublishConfig.Description.Properties = ensureProperties(a.PublishConfig.Description.Properties)
			a.PublishConfig.Description.Properties.Custom = custom
			read, join := a.restrictions(status.BroadcastSetting)
			a.PublishConfig.Description.Properties.System.ReadRestriction = read
			a.PublishConfig.Description.Properties.System.JoinRestriction = join
		}

		if a.SessionReference.ServiceConfigID == uuid.Nil {
			a.SessionReference.ServiceConfigID = uuid.MustParse("4fc10100-5f7a-4470-899b-280835760c07")
		}
		if a.SessionReference.TemplateName == "" {
			a.SessionReference.TemplateName = "MinecraftLobby"
		}
		if a.SessionReference.Name == "" {
			a.SessionReference.Name = strings.ToUpper(uuid.NewString())
		}

		a.Session, err = a.PublishConfig.PublishContext(ctx, a.TokenSource, a.SessionReference)
		if err != nil {
			fmt.Printf("gallery: failed to publish session: %v\n", err)
			return fmt.Errorf("publish: %w", err)
		}
		fmt.Printf("gallery: session published successfully\n")
		return nil
	}

	_, err = a.Session.Commit(ctx, a.description(status, custom))
	if err != nil {
		fmt.Printf("gallery: failed to commit session update: %v\n", err)
	} else {
		fmt.Printf("gallery: session updated successfully\n")
	}
	return err
}

func (a *GalleryAnnouncer) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.Session != nil {
		return a.Session.Close()
	}
	return nil
}

func (a *GalleryAnnouncer) description(status room.Status, custom []byte) *mpsd.SessionDescription {
	read, join := a.restrictions(status.BroadcastSetting)
	return &mpsd.SessionDescription{
		Properties: &mpsd.SessionProperties{
			System: &mpsd.SessionPropertiesSystem{
				ReadRestriction: read,
				JoinRestriction: join,
			},
			Custom: custom,
		},
	}
}

func (a *GalleryAnnouncer) restrictions(setting int32) (read, join string) {
	switch setting {
	case room.BroadcastSettingFriendsOfFriends, room.BroadcastSettingFriendsOnly:
		return mpsd.SessionRestrictionFollowed, mpsd.SessionRestrictionFollowed
	case room.BroadcastSettingInviteOnly:
		return mpsd.SessionRestrictionLocal, mpsd.SessionRestrictionFollowed
	default:
		return mpsd.SessionRestrictionFollowed, mpsd.SessionRestrictionFollowed
	}
}

type statusPayload struct {
	room.Status
	Gallery *galleryPayload `json:"gallery,omitempty"`
}

func ensureProperties(props *mpsd.SessionProperties) *mpsd.SessionProperties {
	if props == nil {
		props = &mpsd.SessionProperties{}
	}
	if props.System == nil {
		props.System = &mpsd.SessionPropertiesSystem{}
	}
	return props
}
