package session

import (
	"encoding/base64"
	"fmt"
	"strings"
)

const (
	GalleryImageTypeScreenshot = "Screenshot"
	GalleryContentTypePNG      = "image/png"
)

type GalleryOptions struct {
	Title string
	Items []GalleryImage
}

type GalleryImage struct {
	Title       string
	Subtitle    string
	URI         string
	Data        []byte
	ContentType string
	ImageType   string
}

func (o GalleryOptions) normalized() GalleryOptions {
	normalized := GalleryOptions{Title: strings.TrimSpace(o.Title)}
	for _, item := range o.Items {
		norm := item.normalized()
		if norm.URI == "" && len(norm.Data) == 0 {
			continue
		}
		normalized.Items = append(normalized.Items, norm)
	}
	return normalized
}

func (o GalleryOptions) payload() *galleryPayload {
	items := make([]galleryItemPayload, 0, len(o.Items))
	for _, item := range o.Items {
		payload := item.payload()
		if payload.URI == "" {
			continue
		}
		items = append(items, payload)
	}
	if len(items) == 0 {
		return nil
	}
	return &galleryPayload{Title: o.Title, Items: items}
}

func (i GalleryImage) normalized() GalleryImage {
	i.Title = strings.TrimSpace(i.Title)
	i.Subtitle = strings.TrimSpace(i.Subtitle)
	i.URI = strings.TrimSpace(i.URI)
	if i.ContentType == "" {
		i.ContentType = GalleryContentTypePNG
	}
	if i.ImageType == "" {
		i.ImageType = GalleryImageTypeScreenshot
	}
	return i
}

func (i GalleryImage) payload() galleryItemPayload {
	uri := i.URI
	if uri == "" && len(i.Data) > 0 {
		uri = fmt.Sprintf("data:%s;base64,%s", i.ContentType, base64.StdEncoding.EncodeToString(i.Data))
	}
	return galleryItemPayload{
		Title:       i.Title,
		Subtitle:    i.Subtitle,
		ImageType:   i.ImageType,
		ContentType: i.ContentType,
		URI:         uri,
	}
}

type galleryPayload struct {
	Title string               `json:"title,omitempty"`
	Items []galleryItemPayload `json:"items"`
}

type galleryItemPayload struct {
	Title       string `json:"title,omitempty"`
	Subtitle    string `json:"subtitle,omitempty"`
	ImageType   string `json:"imageType"`
	ContentType string `json:"contentType"`
	URI         string `json:"uri"`
}
