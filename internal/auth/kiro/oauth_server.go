package kiro

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

type OAuthResult struct {
	Code  string
	State string
	Error string
}

type OAuthServer struct {
	port   int
	server *http.Server
	result chan OAuthResult
}

func NewOAuthServer(port int) *OAuthServer {
	return &OAuthServer{port: port, result: make(chan OAuthResult, 1)}
}

func (s *OAuthServer) Port() int { return s.port }

func (s *OAuthServer) RedirectURI() string {
	return fmt.Sprintf("http://127.0.0.1:%d/oauth/callback", s.port)
}

func (s *OAuthServer) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		res := OAuthResult{Code: q.Get("code"), State: q.Get("state"), Error: q.Get("error")}
		select {
		case s.result <- res:
		default:
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if res.Error != "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("<html><body><h1>Kiro authorization failed</h1><p>You may close this window.</p></body></html>"))
			return
		}
		_, _ = w.Write([]byte("<html><body><h1>Kiro authorization received</h1><p>You may close this window.</p></body></html>"))
	})
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", s.port))
	if err != nil {
		return err
	}
	s.server = &http.Server{Handler: mux}
	go func() { _ = s.server.Serve(listener) }()
	return nil
}

func (s *OAuthServer) WaitForCallback(timeout time.Duration) (*OAuthResult, error) {
	select {
	case res := <-s.result:
		return &res, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("kiro oauth callback timeout")
	}
}

func (s *OAuthServer) Stop(ctx context.Context) error {
	if s.server == nil {
		return nil
	}
	return s.server.Shutdown(ctx)
}
