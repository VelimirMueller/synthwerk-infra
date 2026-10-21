// Command waf serves the Coraza forwardAuth check for the Traefik edge.
//
//	waf              serve /check (forwardAuth) and /healthz on SYNTHWERK_WAF_ADDR
//	waf healthcheck  exit 0 when /healthz answers 200 (compose health check)
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/VelimirMueller/synthwerk-infra/waf"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With(
		"service.name", "synthwerk-waf",
		"deployment.environment.name", os.Getenv("SYNTHWERK_PLATFORM_ENV"),
	)
	addr := os.Getenv("SYNTHWERK_WAF_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		if err := healthcheck(addr); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	if err := run(addr, log); err != nil {
		log.Error("waf stopped", "err", err)
		os.Exit(1)
	}
}

func run(addr string, log *slog.Logger) error {
	cfg, err := waf.ConfigFromEnv(os.Getenv)
	if err != nil {
		return err
	}
	h, err := waf.New(cfg, log)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.Handle("/check", h)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       90 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()
	log.Info("waf listening", "addr", addr, "engine", cfg.Engine, "paranoia_level", cfg.ParanoiaLevel)

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func healthcheck(addr string) error {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("SYNTHWERK_WAF_ADDR: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	url := "http://" + net.JoinHostPort("127.0.0.1", port) + "/healthz"
	// G704: a loopback probe of this process; the port comes from our own config.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody) //nolint:gosec
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req) //nolint:gosec // same G704 as above
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz: status %d", resp.StatusCode)
	}
	return nil
}
