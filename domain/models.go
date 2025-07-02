package domain

import (
	"errors"
	"time"
)

// Ошибки
var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidToken       = errors.New("invalid token")
)

// Контекстные ключи
type contextKey string

const (
	ContextUserIDKey contextKey = "user_id"
	ContextRoleIDKey contextKey = "role_id"
)

// JWT конфигурация
type JWTConfig struct {
	SecretKey string
	ExpiresIn time.Duration
}

type User struct {
	ID       int
	Login    string
	Password string
	RoleID   int
}

type LoginInput struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type TokenResponse struct {
	Token string `json:"token"`
}
