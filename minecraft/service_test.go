package minecraft_test

import (
	"path/filepath"
	"testing"

	"github.com/cjmustard/console-connect/minecraft"
)

func TestNewInitialisesManagers(t *testing.T) {
	dir := t.TempDir()

	opts := minecraft.Options{
		Storage: minecraft.StorageOptions{Directory: filepath.Join(dir, "storage")},
		Gallery: minecraft.GalleryOptions{Path: filepath.Join(dir, "gallery"), Enabled: true},
	}
	opts.ApplyDefaults()

	svc, err := minecraft.New(opts)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	got := svc.Options()
	if got.Storage.Directory == "" {
		t.Fatalf("expected storage directory to be set")
	}
}
