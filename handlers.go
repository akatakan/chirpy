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

const (
	sixtyDays = time.Hour * 24 * 60
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
		Id          uuid.UUID `json:"id"`
		Created_at  time.Time `json:"created_at"`
		Updated_at  time.Time `json:"updated_at"`
		Email       string    `json:"email"`
		IsChirpyRed bool      `json:"is_chirpy_red"`
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
		Id:          createdUser.ID,
		Created_at:  createdUser.CreatedAt,
		Updated_at:  createdUser.UpdatedAt,
		Email:       createdUser.Email,
		IsChirpyRed: createdUser.IsChirpyRed.Bool,
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

func (cfg *apiConfig) handlerLogin(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	type response struct {
		Id           uuid.UUID `json:"id"`
		Created_at   time.Time `json:"created_at"`
		Updated_at   time.Time `json:"updated_at"`
		Email        string    `json:"email"`
		IsChirpyRed  bool      `json:"is_chirpy_red"`
		Token        string    `json:"token"`
		RefreshToken string    `json:"refresh_token"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't decode parameters", err)
		return
	}

	user, err := cfg.db.GetUserByEmail(r.Context(), params.Email)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password", err)
		return
	}

	_, err = auth.CheckPasswordHash(params.Password, user.HashedPassword)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password", err)
		return
	}

	accessToken, err := auth.MakeJWT(
		user.ID,
		cfg.tokenSecret,
		time.Hour,
	)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't create access JWT", err)
		return
	}

	refreshToken := auth.MakeRefreshToken()

	_, err = cfg.db.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
		UserID:    user.ID,
		Token:     refreshToken,
		ExpiresAt: time.Now().UTC().Add(sixtyDays),
	})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't save refresh token", err)
		return
	}

	respondWithJSON(w, http.StatusOK, response{
		Id:           user.ID,
		Created_at:   user.CreatedAt,
		Updated_at:   user.UpdatedAt,
		Email:        user.Email,
		IsChirpyRed:  user.IsChirpyRed.Bool,
		Token:        accessToken,
		RefreshToken: refreshToken,
	})
}

func (c *apiConfig) refreshHandler(w http.ResponseWriter, req *http.Request) {
	type returnVal struct {
		Token string `json:"token"`
	}
	reftoken, err := auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "bad header request", err)
		return
	}
	refresh_token, err := c.db.GetRefreshToken(req.Context(), reftoken)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Cant found refresh token", err)
		return
	}
	if refresh_token.RevokedAt.Valid {
		respondWithError(w, http.StatusUnauthorized, "token revoked", err)
		return
	}
	if time.Now().After(refresh_token.ExpiresAt) {
		respondWithError(w, http.StatusUnauthorized, "token expired", err)
		return
	}
	token, err := auth.MakeJWT(refresh_token.UserID, c.tokenSecret, time.Hour)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "cant create new token", err)
		return
	}
	respondWithJSON(w, http.StatusOK, returnVal{
		Token: token,
	})
}

func (cfg *apiConfig) handlerRevoke(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Couldn't find token", err)
		return
	}

	err = cfg.db.RevokeRefreshToken(r.Context(), refreshToken)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't revoke session", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) updateUser(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	type response struct {
		Id         uuid.UUID `json:"id"`
		Created_at time.Time `json:"created_at"`
		Updated_at time.Time `json:"updated_at"`
		Email      string    `json:"email"`
	}
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err = decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't decode parameters", err)
		return
	}
	userId, err := auth.ValidateJWT(token, cfg.tokenSecret)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	hashedPass := auth.HashPassword(params.Password)
	updatedUser, err := cfg.db.UpdateUser(r.Context(), database.UpdateUserParams{
		Email:          params.Email,
		HashedPassword: hashedPass,
		ID:             userId,
	})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't update user", err)
		return
	}
	respondWithJSON(w, http.StatusOK, response{
		Id:         updatedUser.ID,
		Email:      updatedUser.Email,
		Created_at: updatedUser.CreatedAt,
		Updated_at: updatedUser.UpdatedAt,
	})
}

func (cfg *apiConfig) deleteChirpHandler(w http.ResponseWriter, r *http.Request) {
	chirpId, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Cannot parse id", err)
		return
	}
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Cant get token", err)
		return
	}
	userId, err := auth.ValidateJWT(token, cfg.tokenSecret)
	if err != nil {
		respondWithError(w, http.StatusForbidden, "Unauthorized user", err)
		return
	}
	chirp, err := cfg.db.GetChirpByID(r.Context(), chirpId)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Cannot parse id", err)
		return
	}
	if chirp.UserID != userId {
		respondWithError(w, http.StatusForbidden, "Unauthorized user", err)
		return
	}
	err = cfg.db.DeleteChirpById(r.Context(), chirpId)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "Chirp not found", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) userUpgradeWebhook(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Event string `json:"event"`
		Data  struct {
			UserID string `json:"user_id"`
		} `json:"data"`
	}
	apiKey, err := auth.GetAPIKey(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "cant get api", nil)
		return
	}
	if apiKey != cfg.polkaKey {
		respondWithError(w, http.StatusUnauthorized, "wrong api key", nil)
		return
	}
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	decoder.Decode(&params)
	if params.Event != "user.upgraded" {
		respondWithError(w, http.StatusNoContent, "", nil)
		return
	}
	userID, err := uuid.Parse(params.Data.UserID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "", nil)
		return
	}
	err = cfg.db.UpgradeUser(r.Context(), userID)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "", nil)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
