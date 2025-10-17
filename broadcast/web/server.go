package web

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/cjmustard/consoleconnect/broadcast/account"
	"github.com/cjmustard/consoleconnect/broadcast/friends"
	"github.com/cjmustard/consoleconnect/broadcast/gallery"
	"github.com/cjmustard/consoleconnect/broadcast/logger"
	"github.com/cjmustard/consoleconnect/broadcast/session"
)

type Server struct {
	log      *logger.Logger
	accounts *account.Manager
	sessions *session.Manager
	friends  *friends.Manager
	gallery  *gallery.Manager
	options  func() any
}

func NewServer(log *logger.Logger, accounts *account.Manager, sessions *session.Manager, friends *friends.Manager, gallery *gallery.Manager, options func() any) *Server {
	return &Server{log: log, accounts: accounts, sessions: sessions, friends: friends, gallery: gallery, options: options}
}

func (s *Server) ListenAndServe(ctx context.Context, cfg HTTPOptions) error {
	r := mux.NewRouter()
	r.HandleFunc("/api/accounts", s.handleAccounts).Methods(http.MethodGet)
	r.HandleFunc("/api/sessions", s.handleSessions).Methods(http.MethodGet)
	r.HandleFunc("/api/friends", s.handleFriends).Methods(http.MethodGet)
	r.HandleFunc("/api/config", s.handleConfig).Methods(http.MethodGet)

	httpServer := &http.Server{
		Addr:         cfg.Addr,
		Handler:      r,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	}

	go func() {
		<-ctx.Done()
		ctxShutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(ctxShutdown)
	}()

	s.log.Infof("web manager listening on %s", cfg.Addr)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) handleAccounts(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, s.accounts.All())
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, s.sessionsSnapshot())
}

func (s *Server) handleFriends(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, s.friends.Snapshot())
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if s.options == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	s.writeJSON(w, s.options())
}

type HTTPOptions struct {
	Addr         string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

func (s *Server) writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		s.log.Errorf("write json: %v", err)
	}
}

func (s *Server) sessionsSnapshot() []map[string]any {
	return s.sessions.Snapshot()
}
