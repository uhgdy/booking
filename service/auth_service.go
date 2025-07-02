package service

import (
	"auth_project/domain"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type AuthService struct {
	userRepo domain.UserRepository
	jwtCfg   *domain.JWTConfig
}

func NewAuthService(userRepo domain.UserRepository, jwtCfg *domain.JWTConfig) *AuthService {
	return &AuthService{
		userRepo: userRepo,
		jwtCfg:   jwtCfg,
	}
}

func (s *AuthService) Authenticate(login, password string) (*domain.TokenResponse, error) {
	// поиск пользователя по логину
	user, err := s.userRepo.FindByLogin(login)
	if err != nil {
		return nil, domain.ErrInvalidCredentials
	}

	// проверка пароля (пока что без хеша)
	if user.Password != password {
		return nil, domain.ErrInvalidCredentials
	}

	// создание токена
	claims := &jwt.MapClaims{
		"user_id": user.ID,
		"role_id": user.RoleID,
		"exp":     time.Now().Add(s.jwtCfg.ExpiresIn).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(s.jwtCfg.SecretKey))
	if err != nil {
		return nil, err
	}

	return &domain.TokenResponse{Token: tokenString}, nil
}
