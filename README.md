# Friend Connect

A Minecraft server relay that lets your Xbox Live friends join you on any Minecraft server.

![Friend Connect in Action](https://github.com/cjmustard/friend-connect/blob/main/assets/screenshot.png)

*How Friend Connect appears in your friends' Minecraft server list before configuration*

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
    Logging: friendconnect.LoggingOptions{
        LogConnections: true,  // Log when clients connect and disconnect
        LogTransfers:   true,  // Log when clients are transferred to remote server
        LogFriends:     false, // Disable friend-related logging to reduce noise
        LogSessions:    false, // Disable session announcement logging
        LogNetherNet:   false, // Disable NetherNet signaling logs
        LogErrors:      true,  // Always log errors (recommended)
        Logger:         logger, // Optional custom logger instance
    },
    Logger:     logger,                    // Logger instance for application logging
    ResetTimer: 30 * time.Minute,         // How often to restart service to re-connect the client (default: 30 minutes)
}
```

**Key settings to change:**
- **Remote Server**: Change `RemoteAddress` in `RelayOptions` to your target server
- **Server Name**: Modify `Name` in `ListenerOptions` to change what friends see
- **Friend Settings**: Adjust `AutoAccept` and `AutoAdd` in `FriendOptions`
- **Logging**: Configure `Logging` options to control what gets logged (reduce noise by disabling categories)
- **Custom Logger**: Set `Logger` in `LoggingOptions` to use your own logger instance
- **Reset Timer**: Set `ResetTimer` to control how often the service restarts (default: 30 minutes)

## How to Use

1. Run the service with `./friend-connect`
2. Your friends will see your session in their Xbox Live friend list
3. When they join, they'll be automatically connected to your configured server
4. The service handles all the Xbox Live integration behind the scenes

### Automatic Reset Timer

The service includes an automatic reset timer (default: 30 minutes) that:
- Stops all components to clear ports and connections
- Waits 30 seconds for ports to fully clear
- Restarts all components to refresh the service state
- Helps prevent connection issues and keeps the service running smoothly

You can customize the reset interval by setting `ResetTimer` in the configuration, or disable it by setting it to `0`.

### Logging Configuration

The service includes granular logging controls to reduce log noise. The logging system uses a `ConditionalLogger` that respects your configuration:

- **LogConnections**: Logs when clients connect and disconnect
- **LogTransfers**: Logs when clients are transferred to the remote server  
- **LogFriends**: Logs friend-related activities (requests, additions, etc.)
- **LogSessions**: Logs Xbox Live session announcements and updates
- **LogNetherNet**: Logs NetherNet signaling and connection activities
- **LogErrors**: Logs error messages (recommended to keep enabled)
- **Logger**: Optional custom logger instance for all logging output

You can disable specific categories to reduce log verbosity. For example, to only log connections, transfers, and errors:

```go
Logging: friendconnect.LoggingOptions{
    LogConnections: true,
    LogTransfers:   true,
    LogFriends:     false,
    LogSessions:    false,
    LogNetherNet:   false,
    LogErrors:      true,
    Logger:         logger, // Optional custom logger
},
```

The `ConditionalLogger` automatically filters log messages based on your configuration, so you don't need to change any logging calls in your code - the filtering happens transparently.

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
