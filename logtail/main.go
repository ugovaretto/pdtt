package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/gorilla/websocket"
)

// Message represents the JSON structure for WebSocket communication with clients
// This is sent when files are modified or when listing monitored files
type Message struct {
	Type    string `json:"type"`              // "change" for file updates, "files" for initial file list
	Path    string `json:"path"`              // File path(s) - comma-separated for files type
	Content string `json:"content,omitempty"` // New file content (only for "change" type)
	Size    int64  `json:"size,omitempty"`    // Current file size (only for "change" type)
	Time    int64  `json:"time"`              // Unix timestamp of the event
}

// Client represents an individual WebSocket client connection
// Uses channels for thread-safe communication with the server's event loop
type Client struct {
	conn   *websocket.Conn        // Active WebSocket connection
	send   chan []byte           // Buffered channel for outgoing messages (prevent blocking)
	server *Server               // Reference to parent server for unregistration
}

// Server manages all client connections and file monitoring
// Uses channel-based architecture for thread-safe coordination
type Server struct {
	clients    map[*Client]bool   // Set of active clients (using map for O(1) lookup/delete)
	broadcast  chan []byte       // Channel for broadcasting messages to all clients
	register   chan *Client      // Channel for new client connections
	unregister chan *Client      // Channel for client disconnections
	watcher    *fsnotify.Watcher // File system watcher for monitoring file changes
	paths      map[string]bool   // Set of monitored file paths
	fileStates map[string]int64  // Tracks file reading positions (for incremental reading)
	mu         sync.RWMutex      // Mutex for thread-safe access to shared state
}

// upgrader handles HTTP to WebSocket upgrade requests
// Configured to allow connections from any origin (for development/demo purposes)
// In production, you should implement proper origin checking
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,  // Size of read buffer for WebSocket frames
	WriteBufferSize: 1024,  // Size of write buffer for WebSocket frames
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins for simplicity - SECURITY: Restrict this in production!
	},
}

// verbose is a global flag for enabling detailed logging across all functions
// Set via -v command line flag
var verbose *bool

// NewServer creates and initializes a new Server instance
// Sets up all necessary channels and the file system watcher
// Returns a fully configured server ready to start
func NewServer() *Server {
	// Create file system watcher for monitoring file changes
	// Uses inotify on Linux, kqueue on macOS, etc.
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err) // Fatal error - cannot proceed without file watching capability
	}

	return &Server{
		clients:    make(map[*Client]bool),      // Map for O(1) client lookup and removal
		broadcast:  make(chan []byte),           // Buffered channel to prevent broadcast blocking
		register:   make(chan *Client),          // Channel for new client registration
		unregister: make(chan *Client),          // Channel for client disconnection
		watcher:    watcher,                     // File system event watcher
		paths:      make(map[string]bool),       // Set for tracking monitored files
		fileStates: make(map[string]int64),      // Map for tracking file read positions
	}
}

// addPath adds a file, directory, or glob pattern to the monitoring list
// Handles multiple input types:
// - Regular files: directly added to watcher
// - Directories: recursively walks and adds all files
// - Glob patterns: expands pattern and adds matching files
// Returns error if path doesn't exist and isn't a valid glob pattern
func (s *Server) addPath(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		// Path doesn't exist - check if it's a glob pattern
		if !os.IsNotExist(err) {
			return err // Return other stat errors (permissions, etc.)
		}

		// Try to expand as glob pattern (e.g., *.log, /var/log/*.log)
		matches, err := filepath.Glob(path)
		if err != nil {
			return err // Invalid glob pattern
		}
		if len(matches) == 0 {
			return fmt.Errorf("no files match pattern: %s", path)
		}

		// Recursively add all matching files/directories
		for _, match := range matches {
			if err := s.addPath(match); err != nil {
				log.Printf("Warning: %v", err) // Log but continue processing other matches
			}
		}
		return nil
	}

	// Handle directory vs file
	if info.IsDir() {
		// Recursively walk directory and add all files (not subdirectories)
		return filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
			if err != nil {
				return err // Skip files that can't be accessed
			}
			if !info.IsDir() {
				// Add file to watcher and tracking
				fullPath, _ := filepath.Abs(filePath) // Convert to absolute path for consistency
				s.paths[fullPath] = true
				s.watcher.Add(fullPath)
				return nil
			}
			return nil // Skip directories during walk
		})
	} else {
		// Handle single file
		fullPath, _ := filepath.Abs(path) // Convert to absolute path for consistency
		s.paths[fullPath] = true
		s.watcher.Add(fullPath)
		return nil
	}
}

func (s *Server) getFileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

func (s *Server) readFileChanges(path string, offset int64) (string, int64) {
	file, err := os.Open(path)
	if err != nil {
		return "", offset
	}
	defer file.Close()

	_, err = file.Seek(offset, io.SeekStart)
	if err != nil {
		return "", offset
	}

	scanner := bufio.NewScanner(file)
	var content strings.Builder
	
	for scanner.Scan() {
		content.WriteString(scanner.Text() + "\n")
	}
	
	if err := scanner.Err(); err != nil && err != io.EOF {
		return "", offset
	}

	newOffset := s.getFileSize(path)
	return content.String(), newOffset
}

func (s *Server) handleFileChange(event fsnotify.Event) {
	path := event.Name
	
	if verbose != nil && *verbose {
		log.Printf("File event: %v at %s", event.Op, path)
	}
	
	s.mu.RLock()
	if !s.paths[path] {
		s.mu.RUnlock()
		if verbose != nil && *verbose {
			log.Printf("Path %s not being monitored", path)
		}
		return
	}
	s.mu.RUnlock()

	// Skip if it's just a CHMOD event without content change
	if event.Op&fsnotify.Chmod == fsnotify.Chmod {
		return
	}
	
	// Only process write and create operations (like tail -f)
	// CREATE events happen when files are created or truncated
	if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create {
		// Get current offset
		s.mu.Lock()
		currentOffset := s.fileStates[path]
		s.mu.Unlock()
		
		if event.Op&fsnotify.Create == fsnotify.Create {
			// Reset offset to 0 when file is created or truncated
			currentOffset = 0
		}
		
		if verbose != nil && *verbose {
			log.Printf("Processing %s event for %s, current offset: %d", event.Op, path, currentOffset)
		}
		
		// Read new content
		newContent, newOffset := s.readFileChanges(path, currentOffset)
		
		if verbose != nil && *verbose {
			log.Printf("Read %d bytes of new content from %s, new offset: %d", len(newContent), path, newOffset)
		}
		
		if newContent != "" {
			// Update the offset in the state
			s.mu.Lock()
			s.fileStates[path] = newOffset
			s.mu.Unlock()
			
			// Broadcast the change
			message := Message{
				Type:    "change",
				Path:    path,
				Content: newContent,
				Size:    s.getFileSize(path),
				Time:    time.Now().Unix(),
			}
			
			if verbose != nil && *verbose {
				log.Printf("Broadcasting %d bytes of new content from %s", len(newContent), path)
			}
			
			data, err := json.Marshal(message)
			if err == nil {
				s.broadcast <- data
			}
		}
	}
}

func (s *Server) run() {
	go s.fileWatcher()
	for {
		select {
		case client := <-s.register:
			s.mu.Lock()
			s.clients[client] = true
			s.mu.Unlock()
			log.Printf("Client connected. Total clients: %d", len(s.clients))
			
			// Send initial file list
			s.sendFileList(client)
			
		case client := <-s.unregister:
			s.mu.Lock()
			if _, ok := s.clients[client]; ok {
				delete(s.clients, client)
				close(client.send)
			}
			s.mu.Unlock()
			log.Printf("Client disconnected. Total clients: %d", len(s.clients))
			
		case message := <-s.broadcast:
			s.mu.RLock()
			for client := range s.clients {
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(s.clients, client)
				}
			}
			s.mu.RUnlock()
		}
	}
}

func (s *Server) fileWatcher() {
	for {
		select {
		case event, ok := <-s.watcher.Events:
			if !ok {
				return
			}
			s.handleFileChange(event)
			
		case err, ok := <-s.watcher.Errors:
			if !ok {
				return
			}
			log.Printf("Watcher error: %v", err)
		}
	}
}

func (s *Server) sendFileList(client *Client) {
	s.mu.RLock()
	paths := make([]string, 0, len(s.paths))
	for path := range s.paths {
		paths = append(paths, path)
	}
	s.mu.RUnlock()

	message := Message{
		Type: "files",
		Path: strings.Join(paths, ","),
		Time: time.Now().Unix(),
	}
	
	data, err := json.Marshal(message)
	if err == nil {
		client.send <- data
	}
}

func (c *Client) readPump() {
	defer func() {
		c.server.unregister <- c
		c.conn.Close()
	}()
	
	c.conn.SetReadLimit(1024)
	for {
		_, _, err := c.conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

func (c *Client) writePump() {
	ticker := time.NewTicker(30 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()
	
	for {
		select {
		case message, ok := <-c.send:
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			c.conn.WriteMessage(websocket.TextMessage, message)
			
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func serveWs(server *Server, w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}
	
	client := &Client{
		conn:   conn,
		send:   make(chan []byte, 256),
		server: server,
	}
	
	server.register <- client
	
	go client.writePump()
	go client.readPump()
}

func main() {
	var (
		addr = flag.String("addr", ":8080", "WebSocket server address")
	)
	
	// Set verbose as global variable
	verbose = flag.Bool("v", false, "verbose logging")
	
	flag.Parse()

	if !*verbose {
		log.SetOutput(os.Stdout)
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}

	if flag.NArg() == 0 {
		log.Println("Usage: logtail [OPTIONS] <file/folder/glob>...")
		log.Println("Options:")
		flag.PrintDefaults()
		return
	}

	server := NewServer()
	defer server.watcher.Close()

	// Add all paths from command line arguments
	for _, path := range flag.Args() {
		if err := server.addPath(path); err != nil {
			log.Printf("Error adding path %s: %v", path, err)
		} else {
			log.Printf("Added path: %s", path)
		}
	}

	// Initialize file states
	server.mu.Lock()
	for path := range server.paths {
		server.fileStates[path] = server.getFileSize(path)
	}
	server.mu.Unlock()

	// Start the server
	go server.run()
	
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		serveWs(server, w, r)
	})
	
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "index.html")
	})
	
	log.Printf("Starting WebSocket server on %s", *addr)
	log.Printf("Monitoring %d files", len(server.paths))
	
	err := http.ListenAndServe(*addr, nil)
	if err != nil {
		log.Fatal("Server error:", err)
	}
}