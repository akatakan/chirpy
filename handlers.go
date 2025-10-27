package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/akatakan/chirpy/internal/auth"
	"github.com/akatakan/chirpy/internal/database"
	"github.com/google/uuid"
)

type returnVals struct {
	Id         uuid.UUID `json:"id"`
	Created_at time.Time `json:"created_at"`
	Updated_at time.Time `json:"updated_at"`
	Body       string    `json:"body"`
	User_id    uuid.UUID `json:"user_id"`
}

func healthHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(http.StatusText(http.StatusOK)))
}

func (c *apiConfig) metricHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	template := `<html>
	<body>
		<h1>Welcome, Chirpy Admin</h1>
		<p>Chirpy has been visited %d times!</p>
	</body>
	</html>`
	w.Write([]byte(fmt.Sprintf(template, c.fileserverHits.Load())))
}

func (c *apiConfig) resetHandler(w http.ResponseWriter, req *http.Request) {
	if c.platform != "dev" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	err := c.db.DeleteAllUsers(req.Context())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (c *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		c.fileserverHits.Add(1)
		next.ServeHTTP(w, req)
	})
}

func (c *apiConfig) handlerChirps(w http.ResponseWriter, req *http.Request) {
	type parameters struct {
		Body string `json:"body"`
	}
	decoder := json.NewDecoder(req.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't decode parameters", err)
		return
	}
	token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "cant find token", err)
		return
	}
	userId, err := auth.ValidateJWT(token, c.tokenSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "please log in", err)
		return
	}
	const maxChirpLength = 140
	if len(params.Body) > maxChirpLength {
		respondWithError(w, http.StatusBadRequest, "Chirp is too long", nil)
		return
	}
	createdChirp, err := c.db.CreateChirp(req.Context(), database.CreateChirpParams{
		ID:     uuid.New(),
		Body:   params.Body,
		UserID: userId,
	})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't create chirp", err)
		return
	}
	res := returnVals{
		Id:         createdChirp.ID,
		Created_at: createdChirp.CreatedAt,
		Updated_at: createdChirp.UpdatedAt,
		Body:       createdChirp.Body,
		User_id:    createdChirp.UserID,
	}
	respondWithJSON(w, http.StatusCreated, res)
}

func (c *apiConfig) registerHandler(w http.ResponseWriter, req *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	type userResponse struct {
		Id         uuid.UUID `json:"id"`
		Created_at time.Time `json:"created_at"`
		Updated_at time.Time `json:"updated_at"`
		Email      string    `json:"email"`
	}
	decoder := json.NewDecoder(req.Body)
	var params parameters
	err := decoder.Decode(&params)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	createdUser, err := c.db.CreateUser(req.Context(), database.CreateUserParams{
		ID:             uuid.New(),
		Email:          params.Email,
		HashedPassword: auth.HashPassword(params.Password),
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	respondWithJSON(w, http.StatusCreated, userResponse{
		Id:         createdUser.ID,
		Created_at: createdUser.CreatedAt,
		Updated_at: createdUser.UpdatedAt,
		Email:      createdUser.Email,
	})
}

func (c *apiConfig) getAllChirps(w http.ResponseWriter, req *http.Request) {
	allChirps, err := c.db.GetChirps(req.Context())
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't get chirps", err)
		return
	}
	responseChirps := make([]returnVals, len(allChirps))
	for i, chirp := range allChirps {
		responseChirps[i] = returnVals{
			Id:         chirp.ID,
			Created_at: chirp.CreatedAt,
			Updated_at: chirp.UpdatedAt,
			Body:       chirp.Body,
			User_id:    chirp.UserID,
		}
	}
	respondWithJSON(w, http.StatusOK, responseChirps)
}

func (c *apiConfig) GetChirpById(w http.ResponseWriter, req *http.Request) {
	user_id, err := uuid.Parse(req.PathValue("id"))
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't parse req path value", err)
		return
	}
	chirp, err := c.db.GetChirpByID(req.Context(), user_id)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "User not have any chirp", err)
		return
	}
	res := returnVals{
		Id:         chirp.ID,
		Created_at: chirp.CreatedAt,
		Updated_at: chirp.UpdatedAt,
		Body:       chirp.Body,
		User_id:    chirp.UserID,
	}
	respondWithJSON(w, http.StatusOK, res)
}

func (c *apiConfig) loginHandler(w http.ResponseWriter, req *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	type userResponse struct {
		Id           uuid.UUID `json:"id"`
		Created_at   time.Time `json:"created_at"`
		Updated_at   time.Time `json:"updated_at"`
		Email        string    `json:"email"`
		Token        string    `json:"token"`
		RefreshToken string    `json:"refresh_token"`
	}
	decoder := json.NewDecoder(req.Body)
	var params parameters
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Request parameters are wrong", err)
		return
	}

	existingUser, err := c.db.GetUserByEmail(req.Context(), params.Email)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "Cant find user link to email", err)
		return
	}
	valid, err := auth.CheckPasswordHash(params.Password, existingUser.HashedPassword)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Cant compare pass and hash", err)
		return
	}
	if valid {
		userToken, err := auth.MakeJWT(existingUser.ID, c.tokenSecret, time.Hour)
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, "cannot make jwt", err)
			return
		}
		refreshToken, err := auth.MakeRefreshToken()
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, "cannot make refresh token", err)
			return
		}
		_, err = c.db.CreateRefreshToken(req.Context(), database.CreateRefreshTokenParams{
			Token:     refreshToken,
			UserID:    existingUser.ID,
			ExpiresAt: time.Now().Add(time.Hour * 24 * 60),
		})
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, "cannot create refresh token", err)
			return
		}
		w.Header().Set("Authorization", "Bearer "+userToken)
		respondWithJSON(w, http.StatusOK, userResponse{
			Id:           existingUser.ID,
			Created_at:   existingUser.CreatedAt,
			Updated_at:   existingUser.UpdatedAt,
			Email:        existingUser.Email,
			Token:        userToken,
			RefreshToken: refreshToken,
		})
	} else {
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password", err)
		return
	}
}

func (c *apiConfig) refreshHandler(w http.ResponseWriter, req *http.Request) {
	type returnVal struct {
		Token string `json:"token"`
	}
	token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "bad header request", err)
		return
	}
	refresh_token, err := c.db.GetRefreshToken(req.Context(), token)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Cant found refresh token", err)
		return
	}
	if time.Now().After(refresh_token.ExpiresAt) && !refresh_token.RevokedAt.Valid {
		respondWithError(w, http.StatusUnauthorized, "token expired", err)
		return
	}
	respondWithJSON(w, http.StatusOK, returnVal{
		Token: refresh_token.Token,
	})
}
