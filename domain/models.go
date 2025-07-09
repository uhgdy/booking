package domain

import (
	"errors"
	"time"
)

// Ошибки
var (
	ErrInvalidCredentials = errors.New("неверные учётные данные")
	ErrInvalidToken       = errors.New("некорректный токен")
	ErrRoleNotFound       = errors.New("одна или несколько ролей не найдены")
)

// Контекстные ключи
type contextKey string

const (
	ContextUserIDKey contextKey = "user_id"
	ContextRolesKey  contextKey = "roles"
)

// JWT конфигурация
type JWTConfig struct {
	SecretKey string
	ExpiresIn time.Duration
}

// Роль с подробной информацией
type Role struct {
	ID   int    `json:"id"`
	Name string `json:"name"` // например, "ADMIN", "USER"
}

// Информация о пользователе
type User struct {
	ID       int     `json:"id"`
	Login    string  `json:"login"`
	Password string  `json:"-"` // не отдаём его в ответе
	Name     string  `json:"name"`
	Bio      string  `json:"bio"`
	Roles    []Role  `json:"roles"`
	Salary   float64 `json:"salary"`
}

type LoginInput struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type TokenResponse struct {
	Token string `json:"token"`
}

type UserProfile struct {
	UserID int
	Name   string
	Bio    string
	Salary float64
}

type RegistrationInput struct {
	Login    string  `json:"login" binding:"required,alphanum,min=5,max=50"`
	Password string  `json:"password" binding:"required,min=8"`
	Name     string  `json:"name" binding:"required"`
	Bio      string  `json:"bio" binding:"omitempty,max=500"`
	Salary   float64 `json:"salary" binding:"required,gte=0"`
	RoleIDs  []int   `json:"roles" binding:"required,dive,gt=0"`
}
