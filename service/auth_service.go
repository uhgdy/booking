package service

import (
	"auth_project/domain"
	"log"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

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

func (s *AuthService) GetUserByID(id int) (*domain.User, error) {
	return s.userRepo.FindByID(id)
}

func (s *AuthService) Authenticate(login, password string) (*domain.TokenResponse, error) {
	// поиск пользователя по логину
	user, err := s.userRepo.FindByLogin(login)
	if err != nil {
		log.Printf("[Auth] FindByLogin failed for %q: %v", login, err)
		return nil, domain.ErrInvalidCredentials
	}

	// проверка пароля (пока что без хеша)
	if !strings.HasPrefix(user.Password, "$2a$") {
		if user.Password != password {
			return nil, domain.ErrInvalidCredentials
		}
	} else {
		// проверка с хешом
		log.Printf("[Auth] DB hash for %s: %s", login, user.Password)

		if err := bcrypt.CompareHashAndPassword(
			[]byte(user.Password), // хэш из БД
			[]byte(password),      // введённый пользователем пароль
		); err != nil {
			log.Printf("[Auth] bcrypt mismatch for %q: %v\n", login, err)
			return nil, domain.ErrInvalidCredentials
		}
	}

	// создание токена
	claims := &jwt.MapClaims{
		"user_id": user.ID,
		"roles":   user.Roles,
		"exp":     time.Now().Add(s.jwtCfg.ExpiresIn).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(s.jwtCfg.SecretKey))
	if err != nil {
		return nil, err
	}

	return &domain.TokenResponse{Token: tokenString}, nil
}

// Register создаёт пользователя, его профиль и роли
// Новая — возвращает сразу TokenResponse и ошибку
func (s *AuthService) Register(input *domain.RegistrationInput) (*domain.TokenResponse, error) {
	// Хешируем пароль
	hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	// Сохраняем базовые данные и получаем ID
	u := &domain.User{
		Login:    input.Login,
		Password: string(hash),
	}
	userID, err := s.userRepo.CreateUser(u)
	if err != nil {
		return nil, err
	}
	// Сохраняем профиль с уже известным userID
	profile := &domain.UserProfile{
		UserID: userID,
		Name:   input.Name,
		Bio:    input.Bio,
		Salary: input.Salary,
	}
	if err := s.userRepo.CreateProfile(profile); err != nil {
		return nil, err
	}
	// Проверяем, что все роли существуют
	if err := s.userRepo.ValidateRoles(input.RoleIDs); err != nil {
		return nil, err // или return err, если сервис возвращает только error
	}
	// Привязываем роли
	if err := s.userRepo.AssignRoles(userID, input.RoleIDs); err != nil {
		return nil, err
	}
	// генерируем токен
	claims := jwt.MapClaims{
		"user_id": userID,
		"roles":   input.RoleIDs,
		"exp":     time.Now().Add(s.jwtCfg.ExpiresIn).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(s.jwtCfg.SecretKey))
	if err != nil {
		return nil, err
	}
	return &domain.TokenResponse{Token: tokenString}, nil
}
