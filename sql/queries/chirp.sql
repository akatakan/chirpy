-- name: CreateChirp :one
INSERT INTO chirps (id,created_at,updated_at,user_id, body)
VALUES
( $1, NOW(),NOW(),$2,$3)
RETURNING *;

-- name: GetChirps :many
SELECT * FROM chirps
ORDER BY created_at ASC;

-- name: GetChirpByID :one
SELECT * FROM chirps
WHERE id = $1;

-- name: DeleteChirpById :exec
DELETE FROM chirps
WHERE id = $1;