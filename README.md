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

The project now centres around the root `consoleconnect` package. Create an
`Options` struct, populate it with the accounts and features you need, then
start the service:

```go
opts := consoleconnect.Options{
    Accounts: []consoleconnect.AccountOptions{
        {Gamertag: "CJMustard1452", RefreshToken: "..."},
    },
    Storage: consoleconnect.StorageOptions{Directory: "data"},
    Friends: consoleconnect.FriendOptions{AutoAccept: true, AutoAdd: true},
}
opts.ApplyDefaults()

svc, err := consoleconnect.New(opts)
if err != nil {
    log.Fatalf("initialise broadcaster: %v", err)
}
if err := svc.Run(context.Background()); err != nil {
    log.Fatalf("broadcaster stopped: %v", err)
}
```

## CLI daemon

An example daemon is available in `cmd/broadcasterd`. It exposes a `-listen`
flag to override the Bedrock listener address and otherwise uses the default
options provided by the package. The daemon is only a thin wrapper around the
exported module, making it easy to embed the broadcaster in other applications.

Run it with:

```bash
GO111MODULE=on go run ./cmd/broadcasterd
```

## Tests

A lightweight smoke test ensures that the service boots with a minimal set of
options:

```bash
go test ./...
```
