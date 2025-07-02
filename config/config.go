package config

import "time"

type Config struct {
	DB     DBConfig
	JWT    JWTConfig
	Server ServerConfig
}

type DBConfig struct {
	DSN string
}

type JWTConfig struct {
	SecretKey string
	ExpiresIn time.Duration
}

type ServerConfig struct {
	Port string
}
