// 带路径的文件名
// auth-service/main.go
package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v4" // 确保这一行存在
	"golang.org/x/crypto/bcrypt"
	"shared/database"
)

var jwtSecret = []byte(os.Getenv("JWT_SECRET"))

type User struct {
	ID           uint   `gorm:"primaryKey"`
	Username     string `gorm:"uniqueIndex"`
	PasswordHash string
	Email        string `gorm:"uniqueIndex"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	AppID    string `json:"app_id" binding:"required"`
}

type RegisterRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
	AppID    string `json:"app_id" binding:"required"`
}

func main() {
	// 使用共享的数据库等待功能
	dsn := database.GetDBConfig(
		os.Getenv("DB_HOST"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
	)

	db, err := database.WaitForDB(dsn, 10)
	if err != nil {
		log.Fatal("无法连接数据库:", err)
	}

	// 自动迁移模型
	models := []interface{}{&User{}}
	if err := database.AutoMigrateModels(db, models); err != nil {
		log.Fatal("数据库迁移失败:", err)
	}

	r := gin.Default()

	// 用户注册
	r.POST("/register", func(c *gin.Context) {
		var req RegisterRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// 检查用户名是否已存在
		var existingUser User
		if result := db.Where("username = ?", req.Username).First(&existingUser); result.Error == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "用户名已存在"})
			return
		}

		// 检查邮箱是否已存在
		if result := db.Where("email = ?", req.Email).First(&existingUser); result.Error == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "邮箱已存在"})
			return
		}

		// 创建用户
		passwordHash, err := hashPassword(req.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "密码加密失败"})
			return
		}

		user := User{
			Username:     req.Username,
			PasswordHash: passwordHash,
			Email:        req.Email,
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}

		if result := db.Create(&user); result.Error != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "创建用户失败"})
			return
		}

		// 生成JWT令牌
		token, err := generateJWT(user.ID, user.Username, req.AppID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "生成令牌失败"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "注册成功",
			"token":   token,
			"user": gin.H{
				"id":       user.ID,
				"username": user.Username,
				"email":    user.Email,
			},
		})
	})

	// 用户登录
	r.POST("/login", func(c *gin.Context) {
		var req LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// 查找用户
		var user User
		if result := db.Where("username = ?", req.Username).First(&user); result.Error != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
			return
		}

		// 验证密码
		if !checkPasswordHash(req.Password, user.PasswordHash) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
			return
		}

		// 生成JWT令牌
		token, err := generateJWT(user.ID, user.Username, req.AppID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "生成令牌失败"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "登录成功",
			"token":   token,
			"user": gin.H{
				"id":       user.ID,
				"username": user.Username,
				"email":    user.Email,
			},
		})
	})

	// 验证令牌
	r.POST("/verify", func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "令牌缺失"})
			return
		}

		// 去掉"Bearer "前缀
		if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
			tokenString = tokenString[7:]
		}

		// 解析和验证令牌
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "无效令牌"})
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "无效令牌"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"valid": true,
			"user": gin.H{
				"id":       claims["user_id"],
				"username": claims["username"],
			},
		})
	})

	log.Println("认证服务启动在 :8081")
	r.Run(":8081")
}

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func generateJWT(userID uint, username, appID string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":  userID,
		"username": username,
		"app_id":   appID,
		"exp":      time.Now().Add(time.Hour * 24 * 7).Unix(), // 7天过期
		"iat":      time.Now().Unix(),
	})

	return token.SignedString(jwtSecret)
}
