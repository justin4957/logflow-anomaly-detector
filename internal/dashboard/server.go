package dashboard

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
	"github.com/justin4957/logflow-anomaly-detector/internal/config"
	"github.com/justin4957/logflow-anomaly-detector/pkg/models"
)

//go:embed static/*
var staticFiles embed.FS

// Server provides the web dashboard
type Server struct {
	config    config.DashboardConfig
	upgrader  websocket.Upgrader
	clients   map[*websocket.Conn]bool
	clientsMu sync.RWMutex
	broadcast chan interface{}
}

// NewServer creates a new dashboard server
func NewServer(cfg config.DashboardConfig) *Server {
	return &Server{
		config: cfg,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for development
			},
		},
		clients:   make(map[*websocket.Conn]bool),
		broadcast: make(chan interface{}, 100),
	}
}

// Start starts the dashboard server
func (s *Server) Start(ctx context.Context, input <-chan interface{}) {
	// Start WebSocket broadcaster
	go s.broadcastLoop(ctx)

	// Start input handler
	go s.handleInput(ctx, input)

	// Setup HTTP handlers
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", s.handleWebSocket)
	mux.HandleFunc("/api/metrics", s.handleMetrics)
	mux.HandleFunc("/", s.handleIndex)

	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go func() {
		log.Printf("Dashboard server listening on %s", addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Dashboard server error: %v", err)
		}
	}()

	<-ctx.Done()
	server.Shutdown(context.Background())
}

func (s *Server) handleInput(ctx context.Context, input <-chan interface{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case data, ok := <-input:
			if !ok {
				return
			}
			s.broadcast <- data
		}
	}
}

func (s *Server) broadcastLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case message := <-s.broadcast:
			s.clientsMu.RLock()
			for client := range s.clients {
				err := client.WriteJSON(message)
				if err != nil {
					log.Printf("WebSocket write error: %v", err)
					client.Close()
					s.removeClient(client)
				}
			}
			s.clientsMu.RUnlock()
		}
	}
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}

	s.clientsMu.Lock()
	s.clients[conn] = true
	s.clientsMu.Unlock()

	log.Printf("WebSocket client connected")

	// Keep connection alive
	for {
		if _, _, err := conn.NextReader(); err != nil {
			s.removeClient(conn)
			break
		}
	}
}

func (s *Server) removeClient(conn *websocket.Conn) {
	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()
	delete(s.clients, conn)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	// TODO: Return current metrics snapshot
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
	})
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html>
<head>
    <title>LogFlow Anomaly Detector</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background: #1a1a1a;
            color: #fff;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        h1 {
            color: #4CAF50;
        }
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .metric-card {
            background: #2a2a2a;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #4CAF50;
        }
        .metric-value {
            font-size: 2em;
            font-weight: bold;
            color: #4CAF50;
        }
        .metric-label {
            color: #999;
            font-size: 0.9em;
        }
        .log-stream {
            background: #2a2a2a;
            padding: 20px;
            border-radius: 8px;
            max-height: 400px;
            overflow-y: auto;
            font-family: monospace;
            font-size: 0.9em;
        }
        .anomaly {
            background: #ff5722;
            padding: 15px;
            margin: 10px 0;
            border-radius: 8px;
            border-left: 4px solid #d32f2f;
        }
        .anomaly-high { background: #ff5722; }
        .anomaly-critical { background: #d32f2f; }
        .anomaly-medium { background: #ff9800; }
        .anomaly-low { background: #ffc107; }
        .status {
            color: #4CAF50;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 LogFlow Anomaly Detector</h1>
        <div class="status" id="status">Connecting to server...</div>

        <div class="metrics-grid" id="metrics">
            <div class="metric-card">
                <div class="metric-label">Requests/sec</div>
                <div class="metric-value" id="requests-per-sec">0</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Error Rate</div>
                <div class="metric-value" id="error-rate">0%</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Avg Response Time</div>
                <div class="metric-value" id="response-time">0ms</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Total Requests</div>
                <div class="metric-value" id="total-requests">0</div>
            </div>
        </div>

        <h2>🚨 Recent Anomalies</h2>
        <div id="anomalies"></div>

        <h2>📋 Log Stream</h2>
        <div class="log-stream" id="log-stream"></div>
    </div>

    <script>
        const ws = new WebSocket('ws://' + window.location.host + '/ws');
        const statusEl = document.getElementById('status');
        const anomaliesEl = document.getElementById('anomalies');
        const logStreamEl = document.getElementById('log-stream');
        let totalRequests = 0;

        ws.onopen = () => {
            statusEl.textContent = '✓ Connected';
        };

        ws.onclose = () => {
            statusEl.textContent = '✗ Disconnected';
        };

        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);

            if (data.requests_per_sec !== undefined) {
                // Metrics update
                document.getElementById('requests-per-sec').textContent =
                    data.requests_per_sec.toFixed(2);
                document.getElementById('error-rate').textContent =
                    (data.error_rate * 100).toFixed(2) + '%';
                document.getElementById('response-time').textContent =
                    data.avg_response_time.toFixed(2) + 'ms';
                totalRequests += Math.round(data.requests_per_sec);
                document.getElementById('total-requests').textContent = totalRequests;
            } else if (data.type) {
                // Anomaly detected
                const anomalyDiv = document.createElement('div');
                anomalyDiv.className = 'anomaly anomaly-' + data.severity;
                anomalyDiv.innerHTML = \`
                    <strong>\${data.type.toUpperCase()}</strong> -
                    Severity: \${data.severity} |
                    \${data.description}<br>
                    Metric: \${data.metric} |
                    Expected: \${data.expected_value.toFixed(2)} |
                    Actual: \${data.actual_value.toFixed(2)}
                \`;
                anomaliesEl.insertBefore(anomalyDiv, anomaliesEl.firstChild);

                // Keep only last 10 anomalies
                while (anomaliesEl.children.length > 10) {
                    anomaliesEl.removeChild(anomaliesEl.lastChild);
                }
            } else if (data.message) {
                // Log entry
                const logDiv = document.createElement('div');
                logDiv.textContent = \`[\${data.timestamp}] \${data.level}: \${data.message}\`;
                logStreamEl.insertBefore(logDiv, logStreamEl.firstChild);

                // Keep only last 100 lines
                while (logStreamEl.children.length > 100) {
                    logStreamEl.removeChild(logStreamEl.lastChild);
                }
            }
        };
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}
