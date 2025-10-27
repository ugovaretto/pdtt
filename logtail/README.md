# LogTail - WebSocket File Monitor

A WebSocket server that monitors multiple files like `tail -f` and broadcasts file changes to all connected clients in real-time.

## Features

- **Real-time file monitoring** using efficient file watching
- **WebSocket communication** for instant updates
- **Multiple file support** via glob patterns, file names, or directories
- **Web-based interface** for viewing file changes
- **Automatic reconnection** for robust client connections
- **Cross-platform** (Linux, macOS, Windows)

## Installation

1. Make sure you have Go 1.21 or later installed
2. Clone or download this project
3. Install dependencies:
   ```bash
   go mod tidy
   ```

## Usage

### Basic Usage

```bash
# Monitor a single file
go run main.go /var/log/system.log

# Monitor multiple files
go run main.go /var/log/syslog /var/log/auth.log

# Monitor with glob patterns
go run main.go /var/log/*.log

# Monitor an entire directory
go run main.go /var/log/

# Monitor directory with pattern
go run main.go /var/log/**/*.log
```

### Command Line Options

- `-addr=:8080` - WebSocket server address (default: ":8080")
- `-v` - Enable verbose logging

### Examples

```bash
# Start server on custom port
go run main.go -addr=:9090 /var/log/

# Monitor logs directory with verbose output
go run main.go -v /var/log/

# Monitor specific log files
go run main.go /var/log/nginx/access.log /var/log/nginx/error.log

# Monitor all .log files recursively
go run main.go /var/log/**/*.log
```

## Web Interface

Once the server is running, open your web browser to:
- `http://localhost:8080` (or the address you specified)

The web interface provides:
- Real-time file change display
- List of monitored files
- Timestamp for each change
- Automatic reconnection
- Log clearing functionality

## API

### WebSocket Endpoint

- **URL**: `ws://localhost:8080/ws`
- **Protocol**: WebSocket
- **Format**: JSON messages

### Message Format

#### File Change Message
```json
{
  "type": "change",
  "path": "/var/log/system.log",
  "content": "New log line content...",
  "size": 12345,
  "time": 1699123456
}
```

#### File List Message
```json
{
  "type": "files",
  "path": "/var/log/syslog,/var/log/auth.log",
  "time": 1699123456
}
```

## Testing

1. Start the server:
   ```bash
   go run main.go -v .
   ```

2. Open `http://localhost:8080` in your browser

3. Create or modify files in the monitored directory to see real-time updates

## Dependencies

- `github.com/fsnotify/fsnotify` - File system notifications
- `github.com/gorilla/websocket` - WebSocket implementation

## Building

```bash
# Build for current platform
go build -o logtail

# Build for Linux
GOOS=linux GOARCH=amd64 go build -o logtail-linux

# Build for macOS
GOOS=darwin GOARCH=amd64 go build -o logtail-macos

# Build for Windows
GOOS=windows GOARCH=amd64 go build -o logtail.exe
```

## License

MIT License - feel free to use and modify as needed.