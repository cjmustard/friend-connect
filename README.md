# Console Connect

This repository contains a Go re-implementation of the MCXboxBroadcast broadcaster core.
It uses [gophertunnel](https://github.com/sandertv/gophertunnel) to manage Bedrock
Edition sessions and exposes supporting components that replicate the original
Java service features such as:

- Multi-account Xbox Live presence management.
- Friend list synchronisation with automatic additions and inbound request acceptance.
- MOTD and status broadcasting via gophertunnel with optional relay transfers to a
  downstream Bedrock server.
- Web-based manager that surfaces live account/session/friend data.
- Gallery support for custom user images.
- Persistent storage of friend data using JSON files.

## Layout

All broadcaster source lives under the `github.com/cjmustard/consoleconnect/broadcast`
module path. Subpackages mirror the major areas of the original Java project:

- `account`, `session`, and `subsession` handle Xbox Live presence and session
  bookkeeping.
- `friends` manages friend synchronisation and notifications.
- `gallery`, `storage`, `ping`, and `web` provide optional auxiliary features.
- `notifications` contains the webhook delivery helpers shared by other packages.

The repository root exposes a single `main.go` file so the broadcaster can run as
a standalone executable without any external configuration files.

## Running the broadcaster

Edit `main.go` and populate the `broadcast.Options` struct with the gamertags and
refresh tokens you want to broadcast. Provide a `Relay` `RemoteAddress` if you want
incoming players to receive a Minecraft transfer packet that forwards them to your
own Bedrock server. The sample configuration calls into the
Microsoft device login flow via gophertunnel's auth helpers to cache a refresh
token locally (`assets/token.tok`).

Once the values are set, start the service with:

```bash
GO111MODULE=on go run ./...
```

The program launches the Bedrock listener, synchronises friends on the interval
specified in the options, and serves the web dashboard on the configured HTTP
address.
