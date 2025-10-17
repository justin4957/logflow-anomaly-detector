package stream

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/justin4957/logflow-anomaly-detector/internal/parser"
	"github.com/justin4957/logflow-anomaly-detector/pkg/models"
)

// LogStream handles real-time log file streaming
type LogStream struct {
	logPath   string
	logFormat string
	parser    parser.LogParser
	tailer    FileTailer
}

// FileTailer interface for tailing files
type FileTailer interface {
	Start(ctx context.Context, path string) (<-chan string, error)
	Stop() error
}

// NewLogStream creates a new log stream
func NewLogStream(logPath, logFormat string) *LogStream {
	return &LogStream{
		logPath:   logPath,
		logFormat: logFormat,
		parser:    parser.NewParser(logFormat),
		tailer:    NewTailer(),
	}
}

// Start begins streaming and parsing logs
func (ls *LogStream) Start(ctx context.Context, output chan<- interface{}) {
	lineChan, err := ls.tailer.Start(ctx, ls.logPath)
	if err != nil {
		log.Printf("Failed to start log tailer: %v", err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			ls.tailer.Stop()
			return
		case line, ok := <-lineChan:
			if !ok {
				return
			}

			logEntry, err := ls.parser.Parse(line)
			if err != nil {
				log.Printf("Failed to parse log line: %v", err)
				continue
			}

			output <- logEntry
		}
	}
}

// Tailer implements FileTailer for real-time file tailing
type Tailer struct {
	watcher    *fsnotify.Watcher
	file       *os.File
	reader     *bufio.Reader
	lineChan   chan string
	stopCh     chan struct{}
	offset     int64
	mu         sync.RWMutex
	path       string
	incomplete string // Buffer for incomplete lines
}

// NewTailer creates a new file tailer
func NewTailer() *Tailer {
	return &Tailer{
		lineChan: make(chan string, 100),
		stopCh:   make(chan struct{}),
	}
}

// Start begins tailing the specified file
func (t *Tailer) Start(ctx context.Context, path string) (<-chan string, error) {
	t.mu.Lock()
	t.path = path
	t.mu.Unlock()

	// Open the file
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	t.file = file

	// Seek to end of file to start tailing new content
	offset, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to seek file: %w", err)
	}
	t.offset = offset
	t.reader = bufio.NewReader(file)

	// Create fsnotify watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to create watcher: %w", err)
	}
	t.watcher = watcher

	// Add file to watcher
	if err := watcher.Add(path); err != nil {
		watcher.Close()
		file.Close()
		return nil, fmt.Errorf("failed to watch file: %w", err)
	}

	log.Printf("Started tailing file: %s", path)

	// Start the tailing goroutine
	go t.tailLoop(ctx)

	return t.lineChan, nil
}

// tailLoop is the main loop that watches for file changes
func (t *Tailer) tailLoop(ctx context.Context) {
	defer func() {
		close(t.lineChan)
		log.Printf("Tailer loop stopped")
	}()

	// Ticker for periodic reads (fallback if fsnotify misses events)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("Context cancelled, stopping tailer")
			return

		case <-t.stopCh:
			log.Printf("Stop signal received")
			return

		case event, ok := <-t.watcher.Events:
			if !ok {
				return
			}

			// Handle different event types
			switch {
			case event.Op&fsnotify.Write == fsnotify.Write:
				// File was written to
				t.readNewLines()

			case event.Op&fsnotify.Remove == fsnotify.Remove:
				log.Printf("File removed: %s", event.Name)
				t.handleFileRotation(ctx)

			case event.Op&fsnotify.Rename == fsnotify.Rename:
				log.Printf("File renamed: %s", event.Name)
				t.handleFileRotation(ctx)

			case event.Op&fsnotify.Create == fsnotify.Create:
				log.Printf("File created: %s", event.Name)
				// If watching directory and file was recreated
				if event.Name == t.path {
					t.reopenFile()
				}
			}

		case err, ok := <-t.watcher.Errors:
			if !ok {
				return
			}
			log.Printf("Watcher error: %v", err)

		case <-ticker.C:
			// Periodic check for new content (fallback mechanism)
			t.readNewLines()
		}
	}
}

// readNewLines reads new lines from the file
func (t *Tailer) readNewLines() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.file == nil {
		return
	}

	// Check current file size
	fileInfo, err := t.file.Stat()
	if err != nil {
		log.Printf("Failed to stat file: %v", err)
		return
	}

	currentSize := fileInfo.Size()

	// Check if file was truncated (log rotation scenario)
	if currentSize < t.offset {
		log.Printf("File truncated, resetting to beginning")
		t.offset = 0
		t.file.Seek(0, io.SeekStart)
		t.reader = bufio.NewReader(t.file)
		t.incomplete = ""
		return
	}

	// No new data
	if currentSize == t.offset {
		return
	}

	// Read new lines
	for {
		line, err := t.reader.ReadString('\n')

		if err != nil {
			if err == io.EOF {
				// Save incomplete line for next read
				if line != "" {
					t.incomplete = line
				}
				break
			}
			log.Printf("Error reading file: %v", err)
			break
		}

		// Prepend incomplete line from previous read if any
		if t.incomplete != "" {
			line = t.incomplete + line
			t.incomplete = ""
		}

		// Remove trailing newline
		if len(line) > 0 && line[len(line)-1] == '\n' {
			line = line[:len(line)-1]
		}

		// Remove carriage return if present
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}

		// Skip empty lines
		if line == "" {
			continue
		}

		// Update offset
		newOffset, _ := t.file.Seek(0, io.SeekCurrent)
		t.offset = newOffset

		// Send line to channel (non-blocking)
		select {
		case t.lineChan <- line:
		default:
			log.Printf("Line channel full, dropping line")
		}
	}
}

// handleFileRotation handles log rotation scenarios
func (t *Tailer) handleFileRotation(ctx context.Context) {
	log.Printf("Handling file rotation for: %s", t.path)

	// Wait a bit for the new file to be created
	time.Sleep(100 * time.Millisecond)

	// Try to reopen the file
	t.reopenFile()
}

// reopenFile reopens the file after rotation
func (t *Tailer) reopenFile() {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Close old file
	if t.file != nil {
		t.file.Close()
	}

	// Try to open the new file
	file, err := os.Open(t.path)
	if err != nil {
		log.Printf("Failed to reopen file: %v", err)
		return
	}

	t.file = file
	t.offset = 0
	t.reader = bufio.NewReader(file)
	t.incomplete = ""

	log.Printf("Successfully reopened file: %s", t.path)
}

// Stop stops the file tailer
func (t *Tailer) Stop() error {
	log.Printf("Stopping tailer")

	// Signal stop
	close(t.stopCh)

	t.mu.Lock()
	defer t.mu.Unlock()

	// Close watcher
	if t.watcher != nil {
		if err := t.watcher.Close(); err != nil {
			log.Printf("Error closing watcher: %v", err)
		}
		t.watcher = nil
	}

	// Close file
	if t.file != nil {
		if err := t.file.Close(); err != nil {
			log.Printf("Error closing file: %v", err)
		}
		t.file = nil
	}

	log.Printf("Tailer stopped successfully")
	return nil
}
