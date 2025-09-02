package database

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	redisClient *redis.Client
	onceRedis   sync.Once
)

func InitRedis() {
	onceRedis.Do(func() {
		addr := os.Getenv("REDIS_HOST")
		if addr == "" {
			addr = "localhost:6379"
		}
		password := os.Getenv("REDIS_PASSWORD")
		db := 0

		redisClient = redis.NewClient(&redis.Options{
			Addr:     addr,
			Password: password,
			DB:       db,
		})

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := redisClient.Ping(ctx).Err(); err != nil {
			panic(fmt.Sprintf("failed to connect redis: %v", err))
		}

		fmt.Println("✅ Redis connected:", addr)
	})
}

func GetRedis() *redis.Client {
	if redisClient == nil {
		panic("Redis not initialized, call InitRedis() first")
	}
	return redisClient
}
