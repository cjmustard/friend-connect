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

The project now centres around the exported `minecraft` package. Create an
`Options` struct, pass in the accounts and features you need, then start the
service:

```go
opts := minecraft.Options{
    Accounts: []minecraft.AccountOptions{
        {Gamertag: "CJMustard1452", RefreshToken: "..."},
    },
    Storage: minecraft.StorageOptions{Directory: "data"},
    Friends: minecraft.FriendOptions{AutoAccept: true, AutoAdd: true},
}
opts.ApplyDefaults()

svc, err := minecraft.New(opts)
if err != nil {
    log.Fatalf("initialise broadcaster: %v", err)
}
if err := svc.Run(context.Background()); err != nil {
    log.Fatalf("broadcaster stopped: %v", err)
}
```

A helper `minecraft.LoadOptions` is available when you want to hydrate the
same structure from JSON. The schema mirrors `config.example.json`.

## CLI daemon

An example daemon is available in `cmd/broadcasterd`. It accepts an optional
`-config` flag pointing to a JSON file and a `-listen` flag to override the
Bedrock listener address. The daemon is only a thin wrapper around the exported
module, making it easy to embed the broadcaster in other applications.

Run it with:

```bash
GO111MODULE=on go run ./cmd/broadcasterd -config config.json
```

## Tests

A lightweight smoke test ensures that the service boots with a minimal set of
options:

```bash
go test ./...
```
