package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/akildemir/moneroTss/tss"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// HealthServer to provide something for health check and also p2pid
type MnHealthServer struct {
	logger    zerolog.Logger
	s         *http.Server
	tssServer tss.Server
}

// NewHealthServer create a new instance of health server
func NewMnHealthServer(addr string, tssServer tss.Server) *MnHealthServer {
	hs := &MnHealthServer{
		logger:    log.With().Str("module", "http").Logger(),
		tssServer: tssServer,
	}
	s := &http.Server{
		Addr:    addr,
		Handler: hs.newHandler(),
	}
	hs.s = s
	return hs
}

func (s *MnHealthServer) newHandler() http.Handler {
	router := mux.NewRouter()
	router.Handle("/ping", http.HandlerFunc(s.pingHandler)).Methods(http.MethodGet)
	router.Handle("/p2pid", http.HandlerFunc(s.getP2pIDHandler)).Methods(http.MethodGet)
	return router
}

func (s *MnHealthServer) pingHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (t *MnHealthServer) getP2pIDHandler(w http.ResponseWriter, _ *http.Request) {
	localPeerID := t.tssServer.GetLocalPeerID()
	_, err := w.Write([]byte(localPeerID))
	if err != nil {
		t.logger.Error().Err(err).Msg("fail to write to response")
	}
}

// Start health server
func (t *MnHealthServer) Start() error {
	if t.s == nil {
		return errors.New("invalid http server instance")
	}
	if err := t.s.ListenAndServe(); err != nil {
		if err != http.ErrServerClosed {
			return fmt.Errorf("fail to start http server: %w", err)
		}
	}
	return nil
}

func (t *MnHealthServer) Stop() error {
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := t.s.Shutdown(c)
	if err != nil {
		log.Error().Err(err).Msg("Failed to shutdown the Tss server gracefully")
	}
	return err
}
