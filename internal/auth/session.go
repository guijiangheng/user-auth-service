package auth

import (
	"context"
	"time"
	"user-auth-service/internal/db"

	"github.com/google/uuid"
)

const SessionDuration = 24 * time.Hour

type SessionManager struct {
	Repo *db.UserRepo
}

func NewSessionManager(repo *db.UserRepo) *SessionManager {
	return &SessionManager{Repo: repo}
}

func (m *SessionManager) CreateSession(userId int64) (string, error) {
	sessionId := uuid.New().String()
	expiry := time.Now().Add(SessionDuration)

	return sessionId, m.Repo.CreateSession(userId, sessionId, expiry)
}

func (m *SessionManager) GetUserIdBySessionId(ctx context.Context, sessionId string) (int64, error) {
	newExpiry := time.Now().Add(SessionDuration)

	return m.Repo.GetAndRefreshSession(sessionId, newExpiry)
}
