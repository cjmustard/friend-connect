package consoleconnect_test

import (
	"path/filepath"
	"testing"

	"github.com/cjmustard/console-connect"
)

func TestNewInitialisesManagers(t *testing.T) {
	dir := t.TempDir()

	opts := consoleconnect.Options{
		Storage: consoleconnect.StorageOptions{Directory: filepath.Join(dir, "storage")},
		Gallery: consoleconnect.GalleryOptions{Path: filepath.Join(dir, "gallery"), Enabled: true},
	}
	opts.ApplyDefaults()

	svc, err := consoleconnect.New(opts)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	got := svc.Options()
	if got.Storage.Directory == "" {
		t.Fatalf("expected storage directory to be set")
	}
}
