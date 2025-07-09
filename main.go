package main

import (
	"auth_project/config"
	"auth_project/domain"
	"auth_project/handlers"
	"auth_project/repository/postgres"
	"auth_project/service"
	"context"
	"log"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	// 1. Конфиг
	cfg := config.Config{
		DB: config.DBConfig{DSN: "postgres://ksvistunova:@localhost:5432/booking_system"},
		JWT: config.JWTConfig{
			SecretKey: "supersecretkey",
			ExpiresIn: 2 * time.Hour,
		},
		Server: config.ServerConfig{Port: ":8080"},
	}

	// 2. Подключение к БД
	db, err := pgxpool.New(context.Background(), cfg.DB.DSN)
	if err != nil {
		log.Fatalf("Ошибка подключения к базе: %v", err)
	}
	defer db.Close()

	// 3. Репозиторий
	userRepo := postgres.NewUserRepository(db)

	// 4. Сервис (сюда userRepo уже вписывается без ошибок)
	authService := service.NewAuthService(
		userRepo,
		&domain.JWTConfig{
			SecretKey: cfg.JWT.SecretKey,
			ExpiresIn: cfg.JWT.ExpiresIn,
		},
	)

	// 5. Хэндлер
	authHandler := handlers.NewAuthHandler(authService, cfg.JWT.SecretKey)

	// 6. Маршрутизация
	router := gin.Default()

	// 6.1. Статика
	router.GET("/", func(c *gin.Context) { c.File("./login.html") })
	router.GET("/login", func(c *gin.Context) { c.File("./login.html") })
	router.GET("/profile", func(c *gin.Context) { c.File("./profile.html") })
	router.GET("/profile.html", func(c *gin.Context) { c.File("./profile.html") })

	// 6.2. Публичный API
	router.POST("/api/login", authHandler.Login)
	router.POST("/api/register", authHandler.Register)

	// 6.3. Защищённый API
	protected := router.Group("/api")
	protected.Use(authHandler.GetAuthMiddleware())
	{
		protected.GET("/profile", authHandler.Profile)
		protected.GET("/status", authHandler.Status)
	}

	// 7. Запуск
	log.Printf("Сервер запущен на порту %s", cfg.Server.Port)
	if err := router.Run(cfg.Server.Port); err != nil {
		log.Fatalf("Ошибка старта сервера: %v", err)
	}
}
