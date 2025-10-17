package broadcaster_test

import (
	"path/filepath"
	"testing"

	"github.com/cjmustard/console-connect/broadcaster"
)

func TestNewInitialisesManagers(t *testing.T) {
	dir := t.TempDir()

	opts := broadcaster.Options{
		Storage: broadcaster.StorageOptions{Directory: filepath.Join(dir, "storage")},
		Gallery: broadcaster.GalleryOptions{Path: filepath.Join(dir, "gallery"), Enabled: true},
	}
	opts.ApplyDefaults()

	svc, err := broadcaster.New(opts)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	got := svc.Options()
	if got.Storage.Directory == "" {
		t.Fatalf("expected storage directory to be set")
	}
}
