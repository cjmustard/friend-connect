# Console Connect

Console Connect is a Go re-implementation of the MCXboxBroadcast broadcaster core
using [gophertunnel](https://github.com/sandertv/gophertunnel). It focuses on a
minimal feature set that keeps Xbox Live presence up to date, mirrors the Bedrock
server list entry, and moves friends into your target server automatically.

## Features

- Multi-account Xbox Live presence management driven by refresh tokens.
- Automatic friend synchronisation with optional follow-back and request acceptance.
- Listener that mirrors a downstream Bedrock server's MOTD and transfers players
  to it as soon as they connect.

## Layout

All broadcaster code lives under the `github.com/cjmustard/consoleconnect/broadcast`
module path with these key subpackages:

- `account`, `session`, and `subsession` manage Xbox Live tokens and session
  bookkeeping.
- `friends` handles friend synchronisation and automation.
- `logger`, `nether`, and `xbox` provide shared logging, NetherNet signalling,
  and Xbox token helpers.

The repository root exposes a single `main.go` so the broadcaster can run as a
standalone executable without any external configuration files.

## Running the broadcaster

Edit `main.go` and populate the `broadcast.Options` struct with the gamertags and
refresh tokens you want to broadcast. Provide a `Relay` `RemoteAddress` if you want
incoming players to receive a Minecraft transfer packet that forwards them to your
own Bedrock server. When a relay address is configured the listener mirrors the
remote server's MOTD using `minecraft.NewForeignStatusProvider` and the session
manager pings the target over RakNet before handing players off. If the remote is
unreachable, the joining player receives a disconnect message instead of timing
out. The sample configuration calls into the Microsoft device login flow via
gophertunnel's auth helpers to cache a refresh token locally (`assets/token.tok`).

Once the values are set, start the service with:

```bash
go run .
```

The program launches the Bedrock listener and keeps friends in sync on the
interval specified in the options.
