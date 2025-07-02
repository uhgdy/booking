package main

import (
	"auth_project/config"
	"auth_project/domain"
	"auth_project/handlers"
	"auth_project/repository/postgres"
	"auth_project/service"
	"context"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	// Конфигурация
	cfg := config.Config{
		DB: config.DBConfig{
			DSN: "postgres://ksvistunova:@localhost:5432/booking_system",
		},
		JWT: config.JWTConfig{
			SecretKey: "supersecretkey",
			ExpiresIn: 2 * time.Hour,
		},
		Server: config.ServerConfig{
			Port: ":8080",
		},
	}

	// Инициализация БД
	db, err := pgxpool.New(context.Background(), cfg.DB.DSN)
	if err != nil {
		log.Fatalf("Ошибка подключения к базе: %v", err)
	}
	defer db.Close()

	// Инициализация репозиториев
	userRepo := postgres.NewUserRepository(db)

	// Инициализация сервисов
	authService := service.NewAuthService(userRepo, &domain.JWTConfig{
		SecretKey: cfg.JWT.SecretKey,
		ExpiresIn: cfg.JWT.ExpiresIn,
	})

	// Инициализация обработчиков
	authHandler := handlers.NewAuthHandler(authService, cfg.JWT.SecretKey)

	// Настройка маршрутов
	router := gin.Default()

	router.GET("/", func(c *gin.Context) {
		c.File("./login.html")
	})

	router.GET("/login", func(c *gin.Context) {
		c.File("./login.html")
	})

	router.GET("/profile", func(c *gin.Context) {
		c.File("./profile.html")
	})
	router.GET("/profile.html", func(c *gin.Context) {
		c.File("./profile.html")
	})

	router.POST("/api/login", authHandler.Login)

	// для апи которые требуют авторизации
	protected := router.Group("/api")
	protected.Use(authHandler.GetAuthMiddleware())
	{
		// Маршрут получения данных профиля
		protected.GET("/profile", func(c *gin.Context) {
			userID := c.MustGet(string(domain.ContextUserIDKey)).(int)
			roles := c.MustGet(string(domain.ContextRolesKey)).([]int)

			c.JSON(http.StatusOK, gin.H{
				"user_id": userID,
				"roles":   roles,
			})
		})
	}

	// Запуск сервера
	log.Printf("Сервер стартанул, порт: %s", cfg.Server.Port)
	if err := router.Run(cfg.Server.Port); err != nil {
		log.Fatalf("Ошибка старта сервера: %v", err)
	}
}
