# Console Connect

This repository contains a Go re-implementation of the MCXboxBroadcast broadcaster core.
It uses [gophertunnel](https://github.com/sandertv/gophertunnel) to manage Bedrock
Edition sessions and exposes supporting components that replicate the original
Java service features such as:

- Multi-account Xbox Live presence management.
- Friend list synchronisation with automatic additions.
- MOTD and status broadcasting via gophertunnel.
- Web-based manager that surfaces live account/session/friend data.
- Gallery support for custom user images.
- Persistent storage of friend data using JSON files.

## Getting started

1. Create a configuration file (see `config.example.json`).
2. Run the daemon:

```bash
GO111MODULE=on go run ./cmd/broadcasterd -config config.json
```

## Configuration

The configuration closely mirrors the Java project:

- `accounts`: List of accounts with refresh tokens and metadata.
- `storage.directory`: Path used to persist JSON blobs (friends, gallery metadata, ...).
- `friends`: Settings for automatic friend management.
- `http`: Address and timeouts for the web manager.
- `ping`: Optional UDP ping used to keep upstream services alive.
- `gallery`: Directory where uploaded images are stored.

## Development

The project is organised using internal packages under `internal/broadcaster`. Run `go test ./...`
to execute unit tests once they are added.

