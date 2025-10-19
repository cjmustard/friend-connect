# Friend Connect

A Minecraft server relay that lets your Xbox Live friends join you on any Minecraft server.

## What it does

Friend Connect creates a local Minecraft server that your Xbox Live friends can see and join. When they connect, it automatically relays them to a remote Minecraft server of your choice. This lets you play with friends on any server while appearing as a regular Xbox Live session.

## How it works

1. **Authenticates** with Xbox Live using your Microsoft account
2. **Creates** a local Minecraft server that friends can see in their friend list
3. **Relays** all connections to a remote Minecraft server you specify
4. **Manages** friend requests and automatically adds friends to your session

## Setup

### Prerequisites

- Go 1.24.0 or later
- Xbox Live account with Minecraft access
- Target Minecraft server to relay to

### Building and Running

```bash
git clone https://github.com/cjmustard/friend-connect.git
cd friend-connect
go build -o friend-connect ./cmd
./friend-connect
```

### First Run

On first run, the service will:
1. Open your browser for Xbox Live authentication
2. Ask you to enter a code from the Xbox Live website
3. Save your authentication token in `assets/token.tok`
4. Start the local server on `0.0.0.0:19132`
5. Relay connections to the configured remote server

### Configuration

The service comes with sensible defaults, but you can customize it by editing `cmd/main.go`. Here's the main configuration struct with all available options:

```go
	opts := friendconnect.Options{
		Tokens: []*oauth2.Token{token}, // Xbox Live authentication tokens for connecting to Xbox services
		Friends: friendconnect.FriendOptions{
			AutoAccept: true,             // Automatically accept incoming friend requests without manual approval
			AutoAdd:    true,             // Automatically add accepted friends to the current session
			SyncTicker: 10 * time.Second, // Interval for synchronizing friend list with Xbox Live services
		},
		Listener: friendconnect.ListenerOptions{
			Address: "0.0.0.0:19133",            // Network address and port where the local server will listen for connections, assign to any un-used port
			Name:    "Friend Connect",           // Server name displayed in Minecraft's server browser and friend lists
			Message: "Minecraft Presence Relay", // Server description shown to players when connecting
		},
		Relay: friendconnect.RelayOptions{
			RemoteAddress: "zeqa.net:19132", // Target Minecraft server address that connections will be relayed to
			VerifyTarget:  false,            // Whether to verify the target server is reachable before starting
			Timeout:       5 * time.Second,  // Maximum time to wait when connecting to the target server
		},
		Viewership: session.ViewershipOptions{
			MaxMemberCount:          4,                                     // Maximum number of players allowed to join the session
			MemberCount:             1,                                     // Current number of players currently in the session
			WorldType:               "Survival",                            // Game mode type displayed to players (Survival, Creative, etc.)
			WorldName:               "hostname",                            // Name of the world/server that will be displayed
			HostName:                "username",                            // Name of the session host shown to other players
			Joinability:             room.JoinabilityJoinableByFriends,     // Access control for who can join (friends only, public, etc.)
			BroadcastSetting:        room.BroadcastSettingFriendsOfFriends, // Visibility level determining how the session appears to others
			LanGame:                 false,                                 // Whether this session is restricted to local network only
			OnlineCrossPlatformGame: true,                                  // Enable cross-platform play between PC, mobile, and console
			CrossPlayDisabled:       false,                                 // Disable cross-play functionality between different platforms
		},
		Logger: logger, // Logger instance for application logging and debugging output
	}
```

**Key settings to change:**
- **Remote Server**: Change `RemoteAddress` in `RelayOptions` to your target server
- **Server Name**: Modify `Name` in `ListenerOptions` to change what friends see
- **Friend Settings**: Adjust `AutoAccept` and `AutoAdd` in `FriendOptions`

## How to Use

1. Run the service with `./friend-connect`
2. Your friends will see your session in their Xbox Live friend list
3. When they join, they'll be automatically connected to your configured server
4. The service handles all the Xbox Live integration behind the scenes

## For Developers

If you want to integrate Friend Connect into your own Go application, you can import the library:

```go
import "github.com/cjmustard/friend-connect/friendconnect"
```

Then create your own service instance with custom options:

```go
svc, err := friendconnect.NewWithOptions(opts)
if err != nil {
    log.Fatal(err)
}
svc.Run(context.Background())
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Disclaimer

This tool is for educational and personal use only. Ensure you comply with Xbox Live and Minecraft terms of service when using this software.
