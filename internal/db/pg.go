package db

import (
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type UserRepo struct {
	DB *sql.DB
}

func NewUserRepo(dsn string) (*UserRepo, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	if err = db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	repo := &UserRepo{DB: db}
	if err = repo.initTables(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize tables: %w", err)
	}

	return repo, nil
}

func (r *UserRepo) initTables() error {
	_, err := r.DB.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
		);
	`)
	if err != nil {
		return err
	}

	_, err = r.DB.Exec(`
		CREATE TABLE IF NOT EXISTS sessions (
			session_id TEXT PRIMARY KEY,
			user_id INTEGER REFERENCES users(id) ON DELETE CASCADE NOT NULL,
			expires_at TIMESTAMP WITHOUT TIME ZONE NOT NULL
		);
		CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions (expires_at);
	`)

	return err
}

func (r *UserRepo) CreateUser(username, password string) (int64, error) {
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	var userId int64
	err := r.DB.QueryRow(
		`INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id`,
		username,
		string(hashedPassword),
	).Scan(&userId)

	if err, ok := err.(*pq.Error); ok && err.Code.Name() == "unique_violation" {
		return 0, fmt.Errorf("username already exists")
	} else if err != nil {
		return 0, err
	}

	return userId, nil
}

func (r *UserRepo) GetPasswordHashByUsername(username string) (int64, string, error) {
	var userId int64
	var passwordHash string

	err := r.DB.QueryRow(
		`SELECT id, password_hash FROM users WHERE username = $1`,
		username,
	).Scan(&userId, &passwordHash)

	if err == sql.ErrNoRows {
		return 0, "", fmt.Errorf("user not found")
	}

	return userId, passwordHash, err
}

func (r *UserRepo) CreateSession(userId int64, sessionId string, expiry time.Time) error {
	_, err := r.DB.Exec(`
		INSERT INTO sessions (session_id, user_id, expires_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (session_id)
		DO UPDATE SET user_id = EXCLUDED.user_id, expires_at = EXCLUDED.expires_at`,
		sessionId,
		userId,
		expiry,
	)
	return err
}

func (r *UserRepo) GetAndRefreshSession(sessionId string, newExpiry time.Time) (int64, error) {
	var userId int64

	tx, err := r.DB.Begin()
	if err != nil {
		return 0, err
	}

	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			panic(r)
		}
	}()

	err = tx.QueryRow(`
		SELECT user_id FROM sessions WHERE session_id = $1 AND expires_at > NOW() FOR UPDATE`,
		sessionId,
	).Scan(&userId)

	if err == sql.ErrNoRows {
		tx.Rollback()
		return 0, nil
	} else if err != nil {
		tx.Rollback()
		return 0, err
	}

	_, err = tx.Exec(
		`UPDATE sessions SET expires_at = $1 WHERE session_id = $2`,
		newExpiry,
		sessionId,
	)
	if err != nil {
		tx.Rollback()
		slog.Info(
			"failed to refresh session",
			slog.String("session_id", sessionId),
			slog.String("error", err.Error()))
		return 0, err
	}

	return userId, tx.Commit()
}
