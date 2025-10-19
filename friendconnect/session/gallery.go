package session

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strings"
)

const (
	GalleryImageTypeScreenshot = "Screenshot"
	GalleryContentTypePNG      = "image/png"
	GalleryContentTypeJPEG     = "image/jpeg"
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
	for i, item := range o.Items {
		payload := item.payload()
		if payload.URI == "" {
			log.Printf("gallery: skipping item %d - no URI generated", i)
			continue
		}
		// Log URI length for debugging (data URIs can be very long)
		if len(payload.URI) > 1000 {
			log.Printf("gallery: item %d URI length: %d characters", i, len(payload.URI))
		}
		items = append(items, payload)
	}
	if len(items) == 0 {
		log.Printf("gallery: no valid items found in gallery")
		return nil
	}
	log.Printf("gallery: created payload with %d items", len(items))
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

// LoadGalleryImage loads an image file from the filesystem and creates a GalleryImage.
// This is a public utility function that can be used by other packages to create
// gallery images from local files.
func LoadGalleryImage(path, worldName, hostName string) GalleryImage {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("load gallery image: %v", err)
	}
	return GalleryImage{
		Title:       worldName,
		Subtitle:    hostName,
		Data:        data,
		ContentType: GalleryContentTypeJPEG,
		ImageType:   GalleryImageTypeScreenshot,
	}
}

// LoadGalleryImageWithValidation loads an image file and validates it before creating a GalleryImage.
// This version includes additional validation to ensure the image data is valid and not too large.
func LoadGalleryImageWithValidation(path, worldName, hostName string) (GalleryImage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return GalleryImage{}, fmt.Errorf("read image file: %w", err)
	}

	// Validate image size (limit to 1MB to avoid Xbox Live service issues)
	const maxImageSize = 1024 * 1024 // 1MB
	if len(data) > maxImageSize {
		return GalleryImage{}, fmt.Errorf("image too large: %d bytes (max %d bytes)", len(data), maxImageSize)
	}

	// Validate that we have actual data
	if len(data) == 0 {
		return GalleryImage{}, fmt.Errorf("empty image file")
	}

	return GalleryImage{
		Title:       worldName,
		Subtitle:    hostName,
		Data:        data,
		ContentType: GalleryContentTypeJPEG,
		ImageType:   GalleryImageTypeScreenshot,
	}, nil
}
