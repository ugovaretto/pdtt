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

// Message represents data sent to clients
type Message struct {
	Type    string `json:"type"`
	Path    string `json:"path"`
	Content string `json:"content,omitempty"`
	Size    int64  `json:"size,omitempty"`
	Time    int64  `json:"time"`
}

// Client represents a WebSocket client connection
type Client struct {
	conn   *websocket.Conn
	send   chan []byte
	server *Server
}

// Server holds the application state
type Server struct {
	clients    map[*Client]bool
	broadcast  chan []byte
	register   chan *Client
	unregister chan *Client
	watcher    *fsnotify.Watcher
	paths      map[string]bool
	fileStates map[string]int64
	mu         sync.RWMutex
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins for simplicity
	},
}

var verbose *bool

func NewServer() *Server {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}

	return &Server{
		clients:    make(map[*Client]bool),
		broadcast:  make(chan []byte),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		watcher:    watcher,
		paths:      make(map[string]bool),
		fileStates: make(map[string]int64),
	}
}

func (s *Server) addPath(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		// Check if it's a glob pattern
		matches, err := filepath.Glob(path)
		if err != nil {
			return err
		}
		if len(matches) == 0 {
			return fmt.Errorf("no files match pattern: %s", path)
		}
		for _, match := range matches {
			if err := s.addPath(match); err != nil {
				log.Printf("Warning: %v", err)
			}
		}
		return nil
	}

	if info.IsDir() {
		return filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() {
				fullPath, _ := filepath.Abs(filePath)
				s.paths[fullPath] = true
				s.watcher.Add(fullPath)
				return nil
			}
			return nil
		})
	} else {
		fullPath, _ := filepath.Abs(path)
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