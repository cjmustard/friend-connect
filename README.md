# Friend Connect

A Minecraft server relay that lets your Xbox Live friends join you on any Minecraft server.

![Friend Connect in Action](https://github.com/cjmustard/friend-connect/blob/main/assets/screenshot.png)

*How Friend Connect appears in your friends' Minecraft server list*

## What it does

Friend Connect creates a local Minecraft server that your Xbox Live friends can see and join. When they connect, it automatically relays them to a remote Minecraft server of your choice. This lets you play with friends on any server while appearing as a regular Xbox Live session.

## How it works

1. **Authenticates** with Xbox Live using your Microsoft account
2. **Creates** a local Minecraft server that friends can see in their friend list
3. **Relays** all connections to a remote Minecraft server you specify
4. **Manages** friend requests and automatically adds friends to your session

## Setup

### Prerequisites

- Go 1.21 or later
- Xbox Live account with Minecraft access
- Target Minecraft server to relay to

### Building and Running

```bash
git clone https://github.com/cjmustard/friend-connect.git
cd friend-connect
go build -o friend-connect ./example
./friend-connect
```

### First Run

On first run, the service will:
1. Open your browser for Xbox Live authentication
2. Ask you to enter a code from the Xbox Live website
3. Save your authentication token in `assets/token.tok`
4. Start the local server on `0.0.0.0:19133`
5. Relay connections to the configured remote server

### Configuration

The service comes with sensible defaults, but you can customize it by editing `example/main.go`. Here's the main configuration:

```go
opts := friendconnect.Options{
    Tokens: []*oauth2.Token{token}, // Xbox Live authentication tokens
    Friends: friendconnect.FriendOptions{
        AutoAccept: true,             // Automatically accept incoming friend requests
        AutoAdd:    true,             // Automatically add accepted friends to session
        SyncTicker: 20 * time.Second, // Interval for synchronizing friend list (rate limits when under 20s)
    },
    Listener: friendconnect.ListenerOptions{
        Address: "0.0.0.0:19133",            // Local server address and port
        Name:    "Friend Connect",           // Server name displayed to friends
        Message: "Minecraft Presence Relay", // Server description
    },
    Relay: friendconnect.RelayOptions{
        RemoteAddress: "zeqa.net:19132", // Target Minecraft server address
        VerifyTarget:  false,            // Whether to verify target server is reachable
        Timeout:       5 * time.Second,  // Connection timeout for target server
    },
    Viewership: session.ViewershipOptions{
        MaxMemberCount:          4,                                     // Maximum players allowed
        MemberCount:             1,                                     // Current player count
        WorldType:               "Survival",                            // Game mode type
        WorldName:               "hostname",                            // World/server name displayed
        HostName:                "username",                            // Session host name
        Joinability:             room.JoinabilityJoinableByFriends,     // Access control
        BroadcastSetting:        room.BroadcastSettingFriendsOfFriends, // Visibility level
        LanGame:                 false,                                 // Local network only
        OnlineCrossPlatformGame: true,                                  // Enable cross-platform play
        CrossPlayDisabled:       false,                                 // Disable cross-play
    },
    Logger: logger, // Logger instance for application logging
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

If you want to integrate Friend Connect into your own Go application:

```go
import "github.com/cjmustard/friend-connect/friendconnect"

svc, err := friendconnect.NewWithOptions(context.Background(), opts)
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