package main

import (
	"log"
	"net/http"
	"sync/atomic"
)

type apiConfig struct {
	fileserverHits atomic.Int32
}

func main() {
	mux := http.NewServeMux()
	cfg := apiConfig{
		fileserverHits: atomic.Int32{},
	}
	filepathRoot := "/"
	mux.HandleFunc("/healthz/", healthHandler)
	mux.HandleFunc("/metrics/", cfg.metricHandler)
	mux.HandleFunc("/reset/", cfg.resetHandler)
	handler := http.StripPrefix("/app", cfg.middlewareMetricsInc(http.FileServer(http.Dir("."))))
	mux.Handle("/", handler)
	port := "8080"
	srv := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	log.Printf("Serving files from %s on port: %s\n", filepathRoot, port)
	log.Fatal(srv.ListenAndServe())
}
