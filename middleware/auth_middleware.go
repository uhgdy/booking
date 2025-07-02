package middleware

import (
	"auth_project/domain"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func AuthMiddleware(jwtSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {

		// проверка заголовка авторизации
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			return
		}

		// извлеченеи токена
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Bearer token not found"})
			return
		}

		// парсинг токена
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, domain.ErrInvalidToken
			}
			return []byte(jwtSecret), nil
		})

		// обработка ошибок
		if err != nil {
			log.Printf("JWT validation error: %v", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		if !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		// извлечение данных из токена
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			return
		}

		userID, ok := claims["user_id"].(float64)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID in token"})
			return
		}

		// Обработка ролей
		rolesClaim, ok := claims["roles"]
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Roles claim is required"})
			return
		}

		var roles []int

		// Обрабатываем разные форматы ролей
		switch v := rolesClaim.(type) {
		case []interface{}:
			for _, role := range v {
				if roleID, ok := role.(float64); ok {
					roles = append(roles, int(roleID))
				}
			}
		case []float64:
			for _, roleID := range v {
				roles = append(roles, int(roleID))
			}
		case float64:
			roles = append(roles, int(v))
		default:
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid roles format"})
			return
		}

		// Добавляем в контекст
		c.Set(string(domain.ContextUserIDKey), int(userID))
		c.Set(string(domain.ContextRolesKey), roles)

		c.Next()
	}
}
