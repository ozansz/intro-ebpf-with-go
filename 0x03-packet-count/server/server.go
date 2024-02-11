package server

import (
	"bytes"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

var (
	// go:embed index.html
	indexTemplate string
)

const (
	defaultPort = "8080"
)

type client struct {
	conn *websocket.Conn
}

type Server struct {
	port      string
	upgrader  websocket.Upgrader
	clients   map[*client]bool
	indexPage string

	data      map[time.Time]any
	dataSer   atomic.Value
	broadcast chan any
}

type Option func(*Server)

func WithPort(port string) Option {
	return func(s *Server) {
		s.port = port
	}
}

func New(opts ...Option) (*Server, error) {
	s := &Server{
		port:      defaultPort,
		clients:   make(map[*client]bool),
		data:      make(map[time.Time]any),
		broadcast: make(chan any),
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin:     func(r *http.Request) bool { return true },
		},
	}

	indexTmpl, err := template.New("index-page").Parse(indexTemplate)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := indexTmpl.Execute(&buf, s.port); err != nil {
		return nil, err
	}
	s.indexPage = buf.String()

	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

func (s *Server) Start() {
	http.HandleFunc("/", s.serveIndex)
	http.HandleFunc("/json", s.serveJSON)
	http.HandleFunc("/ws", s.handleConnections)

	go s.handleBroadcast()
	go func() {
		log.Printf("server started on :%s", s.port)
		if err := http.ListenAndServe(":"+s.port, nil); err != nil {
			log.Fatalf("listen http: %v", err)
		}
	}()
}

func (s *Server) Submit(data any) {
	s.broadcast <- data
}

func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed: "+r.Method, http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(s.indexPage))
}

func (s *Server) serveJSON(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	val := s.dataSer.Load()
	if val == nil {
		w.Write([]byte("{}"))
		return
	}

	b := val.([]byte)
	w.Write(b)
}

func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	ws, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Error upgrading websocket: %v", err)
		return
	}
	defer ws.Close()

	client := &client{conn: ws}
	s.clients[client] = true

	for {
		_, _, err := ws.ReadMessage()
		if err != nil {
			log.Printf("Error reading websocket message: %v", err)
			delete(s.clients, client)
			break
		}
	}
}

func (s *Server) handleBroadcast() {
	for {
		msg := <-s.broadcast
		s.data[time.Now().UTC()] = msg
		b, err := json.Marshal(s.data)
		if err != nil {
			log.Printf("Error encoding JSON: %v", err)
			continue
		}

		s.dataSer.Store(b)

		for client := range s.clients {
			err := client.conn.WriteMessage(websocket.TextMessage, b)
			if err != nil {
				log.Printf("Error writing websocket message: %v", err)
				client.conn.Close()
				delete(s.clients, client)
			}
		}
	}
}
