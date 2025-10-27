package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"
	"sync/atomic"

	"github.com/akatakan/chirpy/internal/database"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	platform       string
	tokenSecret    string
	polkaKey       string
}

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	tokenSecret := os.Getenv("TOKEN_SECRET")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal(err)
	}
	dbQueries := database.New(db)
	const filePath = "."
	const port = "8080"
	mux := http.NewServeMux()
	cfg := apiConfig{
		fileserverHits: atomic.Int32{},
		db:             dbQueries,
		platform:       os.Getenv("PLATFORM"),
		tokenSecret:    tokenSecret,
		polkaKey:       os.Getenv("POLKA_KEY"),
	}
	mux.HandleFunc("GET /api/healthz", healthHandler)
	mux.HandleFunc("GET /admin/metrics", cfg.metricHandler)
	mux.HandleFunc("POST /admin/reset", cfg.resetHandler)
	mux.HandleFunc("GET /api/chirps", cfg.getAllChirps)
	mux.HandleFunc("GET /api/chirps/{id}", cfg.GetChirpById)
	mux.HandleFunc("POST /api/chirps", cfg.handlerChirps)
	mux.HandleFunc("POST /api/users", cfg.registerHandler)
	mux.HandleFunc("POST /api/login", cfg.handlerLogin)
	mux.HandleFunc("POST /api/refresh", cfg.refreshHandler)
	mux.HandleFunc("POST /api/revoke", cfg.handlerRevoke)
	mux.HandleFunc("PUT /api/users", cfg.updateUser)
	mux.HandleFunc("DELETE /api/chirps/{id}", cfg.deleteChirpHandler)
	mux.HandleFunc("POST /api/polka/webhooks", cfg.userUpgradeWebhook)
	handler := http.StripPrefix("/app", cfg.middlewareMetricsInc(http.FileServer(http.Dir(filePath))))
	mux.Handle("/app/", handler)
	srv := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	log.Printf("Serving files from %s on port: %s\n", filePath, port)
	log.Fatal(srv.ListenAndServe())
}
