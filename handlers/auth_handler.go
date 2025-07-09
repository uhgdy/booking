package handlers

import (
	"auth_project/domain"
	"auth_project/middleware"
	"auth_project/service"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	authService *service.AuthService
	jwtSecret   string
}

func NewAuthHandler(authService *service.AuthService, jwtSecret string) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		jwtSecret:   jwtSecret,
	}
}

func (h *AuthHandler) Login(c *gin.Context) {
	// 1. Парсинг входных данных
	var input domain.LoginInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// 2. Аутентификация через сервис
	token, err := h.authService.Authenticate(input.Login, input.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// 3. Успешный ответ с токеном
	c.JSON(http.StatusOK, token)
}

func (h *AuthHandler) Profile(c *gin.Context) {
	// 1) Забираем user_id из контекста, который поставил middleware
	uidAny, exists := c.Get(string(domain.ContextUserIDKey))
	userID := uidAny.(int)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found in context"})
		return
	}

	// 2) Через сервис (или напрямую через репозиторий) подгружаем полный профиль
	user, err := h.authService.GetUserByID(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cannot load user"})
		return
	}

	// 3) Не отдаем пароль
	user.Password = ""

	// 4) Отдаем JSON со всем объектом
	c.JSON(http.StatusOK, user)

}

// возвращает middleware для аутентификации токена
func (h *AuthHandler) GetAuthMiddleware() gin.HandlerFunc {
	return middleware.AuthMiddleware(h.jwtSecret)
}

// Status — проверяет, авторизован ли пользователь.
// Если токен валиден, middleware пропустит сюда запрос и вернет 200.
func (h *AuthHandler) Status(c *gin.Context) {

	c.JSON(http.StatusOK, gin.H{
		"authorized": true,
	})
}

/* func (h *AuthHandler) Register(c *gin.Context) {
	// 1. Парсинг входных данных
	var input domain.LoginInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// 2. Аутентификация через сервис
	token, err := h.authService.Authenticate(input.Login, input.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// 3. Успешный ответ с токеном
	c.JSON(http.StatusOK, token)
} */

// Register обрабатывает POST /api/register
func (h *AuthHandler) Register(c *gin.Context) {
	var input domain.RegistrationInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	tokenResp, err := h.authService.Register(&input)
	if err != nil {
		// Если ошибка ErrRoleNotFound, вернём 400 Bad Request
		if errors.Is(err, domain.ErrRoleNotFound) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		// Иначе — внутренняя ошибка
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, tokenResp)

}
