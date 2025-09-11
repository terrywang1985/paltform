// auth-service/main.go
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"shared/database"
)

var jwtSecret = []byte(os.Getenv("JWT_SECRET"))
var internalSharedToken = os.Getenv("SHARED_INTERNAL_TOKEN") // 给游戏服/后端调用的共享密钥

// ===== Models =====
type User struct {
	ID            uint   `gorm:"primaryKey"`
	OpenID        string `gorm:"type:char(36);uniqueIndex"`
	Username      string `gorm:"type:varchar(100);uniqueIndex"`
	PasswordHash  string
	Email         string `gorm:"type:varchar(255);uniqueIndex"`
	CountryCode   string `gorm:"type:varchar(5);default:'+86'"`
	Phone         string `gorm:"type:varchar(20)"`
	PhoneVerified bool   `gorm:"default:false"`
	FirstName     string `gorm:"type:varchar(100)"`
	LastName      string `gorm:"type:varchar(100)"`
	Avatar        string `gorm:"type:varchar(255)"`
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	AppID    string `json:"app_id" binding:"required"`
	DeviceID string `json:"device_id"` // 可选：用于日志/定位
}

type RegisterRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
	AppID    string `json:"app_id" binding:"required"`
}

type SMSRequest struct {
	CountryCode string `json:"country_code" binding:"required"`
	Phone       string `json:"phone" binding:"required"`
	AppID       string `json:"app_id" binding:"required"`
	DeviceID    string `json:"device_id"`
}

type PhoneLoginRequest struct {
	CountryCode string `json:"country_code" binding:"required"`
	Phone       string `json:"phone" binding:"required"`
	Code        string `json:"code" binding:"required"`
	AppID       string `json:"app_id" binding:"required"`
	DeviceID    string `json:"device_id"`
}

// 登出请求
type LogoutRequest struct {
	LogoutAll bool `json:"logout_all"` // 是否登出所有设备
}

type CheckTokenRequest struct {
	Token string `json:"token" binding:"required"`
	AppID string `json:"app_id" binding:"required"`
}

type KickRequest struct {
	OpenID string `json:"openid"`  // openid 与 user_id 任选其一
	UserID *uint  `json:"user_id"` // 可选
	AppID  string `json:"app_id" binding:"required"`
	Reason string `json:"reason"` // 可选
}

// ===== Keys in Redis =====
func tokenBlacklistKey(jti string) string {
	return "token:blacklist:" + jti
}
func currentSessionKey(appID string, userID uint) string {
	return fmt.Sprintf("session:current:%s:%d", appID, userID)
}

// ===== Main =====
func main() {
	// DB
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

	// Redis
	database.InitRedis()

	// AutoMigrate
	models := []interface{}{&User{}}
	if err := database.AutoMigrateModels(db, models); err != nil {
		log.Fatal("数据库迁移失败:", err)
	}

	r := gin.Default()

	// 注册
	r.POST("/register", func(c *gin.Context) {
		var req RegisterRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		var existing User
		if result := db.Where("username = ?", req.Username).First(&existing); result.Error == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "用户名已存在"})
			return
		}
		if result := db.Where("email = ?", req.Email).First(&existing); result.Error == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "邮箱已存在"})
			return
		}

		hash, err := hashPassword(req.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "密码加密失败"})
			return
		}

		uid := uuid.NewString()
		user := User{
			OpenID:       uid,
			Username:     req.Username,
			PasswordHash: hash,
			Email:        req.Email,
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}
		if result := db.Create(&user); result.Error != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "创建用户失败"})
			return
		}

		// 单点登录：创建 session_id 并写入 Redis
		sessionID := uuid.NewString()
		if err := setCurrentSession(c, req.AppID, user.ID, sessionID, time.Hour*24*7); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "创建会话失败"})
			return
		}

		token, jti, err := generateJWT(user, req.AppID, sessionID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "生成令牌失败"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "注册成功",
			"token":   token,
			"openid":  user.OpenID,
			"user": gin.H{
				"username": user.Username,
				"email":    user.Email,
			},
			"jti": jti,
		})
	})

	// 登录（用户名密码）
	r.POST("/login", func(c *gin.Context) {
		var req LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		var user User
		if result := db.Where("username = ?", req.Username).First(&user); result.Error != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
			return
		}
		if !checkPasswordHash(req.Password, user.PasswordHash) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
			return
		}

		sessionID := uuid.NewString()
		if err := setCurrentSession(c, req.AppID, user.ID, sessionID, time.Hour*24*7); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "会话创建失败"})
			return
		}

		token, jti, err := generateJWT(user, req.AppID, sessionID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "生成令牌失败"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "登录成功",
			"token":   token,
			"openid":  user.OpenID,
			"user": gin.H{
				"username": user.Username,
				"email":    user.Email,
			},
			"jti": jti,
		})
	})

	// 短信
	r.POST("/phone/send-code", sendSMSHandler(db))
	r.POST("/phone/login", phoneLoginHandler(db))

	// 客户端验证令牌（简单版）
	r.POST("/verify", func(c *gin.Context) {
		tokenString, ok := extractBearer(c)
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": "令牌缺失"})
			return
		}
		claims, err := parseAndValidateClaims(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "无效令牌"})
			return
		}
		// 黑名单 & 单点登录检查
		if ok := isTokenUsable(c, claims); !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "令牌已失效"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"valid":    true,
			"user_id":  claims["user_id"],
			"username": claims["username"],
			"openid":   claims["sub"],
			"app_id":   claims["app_id"],
		})
	})

	// 登出（把 jti 加入黑名单）
	r.POST("/logout", func(c *gin.Context) {
		tokenString, ok := extractBearer(c)
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": "令牌缺失"})
			return
		}
		token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})
		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "无效令牌"})
			return
		}
		claims, _ := token.Claims.(jwt.MapClaims)

		jti := fmt.Sprint(claims["jti"])
		expFloat, _ := claims["exp"].(float64)
		exp := time.Unix(int64(expFloat), 0)
		ttl := time.Until(exp)
		if ttl < 0 {
			ttl = 0
		}

		if err := addToBlacklist(c, jti, ttl); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "登出失败"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "已登出"})
	})

	// ======= 服务端（游戏服/后端）调用的接口 =======

	// 令牌校验（详细、带 openid），需要 X-Internal-Auth
	r.POST("/check-token", internalAuthMiddleware, func(c *gin.Context) {
		var req CheckTokenRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		claims, err := parseAndValidateClaims(req.Token)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"valid": false, "reason": "invalid_token"})
			return
		}
		// 黑名单 & 单点登录
		if ok := isTokenUsable(c, claims); !ok {
			c.JSON(http.StatusOK, gin.H{"valid": false, "reason": "revoked_or_kicked"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"valid":      true,
			"openid":     claims["sub"],
			"user_id":    claims["user_id"],
			"username":   claims["username"],
			"app_id":     claims["app_id"],
			"session_id": claims["session_id"],
			"exp":        claims["exp"],
			"iat":        claims["iat"],
			"jti":        claims["jti"],
		})
	})

	// 踢人：强制失效当前会话（单点登录机制），需要 X-Internal-Auth
	r.POST("/sessions/kick", internalAuthMiddleware, func(c *gin.Context) {
		var req KickRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		var user User
		if req.OpenID != "" {
			if result := db.Where("open_id = ? OR openid = ?", req.OpenID, req.OpenID).First(&user); result.Error != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "用户不存在"})
				return
			}
		} else if req.UserID != nil {
			if result := db.Where("id = ?", *req.UserID).First(&user); result.Error != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "用户不存在"})
				return
			}
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "需要 openid 或 user_id"})
			return
		}
		// 设置一个新的随机 session_id，旧 token 会失效
		newSessionID := uuid.NewString()
		if err := setCurrentSession(c, req.AppID, user.ID, newSessionID, time.Hour*24*7); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "踢人失败"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"message":     "已踢下线",
			"openid":      user.OpenID,
			"user_id":     user.ID,
			"app_id":      req.AppID,
			"new_session": newSessionID,
			"reason":      req.Reason,
		})
	})

	log.Println("认证服务启动在 :8081")
	r.Run(":8081")
}

// ===== Helpers =====
func internalAuthMiddleware(c *gin.Context) {
	if internalSharedToken == "" {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "服务端共享密钥未配置"})
		return
	}
	if c.GetHeader("X-Internal-Auth") != internalSharedToken {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "未授权"})
		return
	}
	c.Next()
}

func extractBearer(c *gin.Context) (string, bool) {
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		return "", false
	}
	if len(tokenString) > 7 && strings.HasPrefix(tokenString, "Bearer ") {
		tokenString = tokenString[7:]
	}
	return tokenString, true
}

func addToBlacklist(c *gin.Context, jti string, ttl time.Duration) error {
	rdb := database.GetRedis()
	if jti == "" {
		return nil
	}
	return rdb.Set(context.Background(), tokenBlacklistKey(jti), "1", ttl).Err()
}

func isBlacklisted(ctx context.Context, jti string) bool {
	if jti == "" {
		return false
	}
	rdb := database.GetRedis()
	exists, _ := rdb.Exists(ctx, tokenBlacklistKey(jti)).Result()
	return exists > 0
}

func setCurrentSession(c *gin.Context, appID string, userID uint, sessionID string, ttl time.Duration) error {
	rdb := database.GetRedis()
	return rdb.Set(context.Background(), currentSessionKey(appID, userID), sessionID, ttl).Err()
}

func getCurrentSession(c *gin.Context, appID string, userID uint) (string, error) {
	rdb := database.GetRedis()
	return rdb.Get(context.Background(), currentSessionKey(appID, userID)).Result()
}

func parseAndValidateClaims(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		return nil, errors.New("invalid token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims")
	}
	// 过期校验（jwt.Parse 已做，但这里稳妥检查）
	if exp, ok := claims["exp"].(float64); ok {
		if time.Now().After(time.Unix(int64(exp), 0)) {
			return nil, errors.New("expired")
		}
	}
	return claims, nil
}

func isTokenUsable(c *gin.Context, claims jwt.MapClaims) bool {
	ctx := context.Background()
	jti := fmt.Sprint(claims["jti"])
	if isBlacklisted(ctx, jti) {
		return false
	}
	// 单点登录校验：token.session_id 必须等于 Redis 中当前 session_id
	appID := fmt.Sprint(claims["app_id"])
	userIDAny := claims["user_id"]
	var userID uint
	switch v := userIDAny.(type) {
	case float64:
		userID = uint(v)
	case int:
		userID = uint(v)
	case uint:
		userID = v
	default:
		return false
	}
	sessionIDToken := fmt.Sprint(claims["session_id"])
	sessionIDCurrent, err := getCurrentSession(c, appID, userID)
	if err != nil {
		return false
	}
	return sessionIDToken == sessionIDCurrent
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

func generateJWT(user User, appID string, sessionID string) (string, string, error) {
	jti := uuid.NewString()
	exp := time.Now().Add(7 * 24 * time.Hour) // 7天
	claims := jwt.MapClaims{
		"sub":        user.OpenID, // openid
		"user_id":    user.ID,
		"username":   user.Username,
		"app_id":     appID,
		"session_id": sessionID, // 单点登录关键字段
		"jti":        jti,       // 令牌ID，用于黑名单
		"exp":        exp.Unix(),
		"iat":        time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(jwtSecret)
	return signed, jti, err
}

// ========= 下面是短信/手机号登录相关与你原来的逻辑一致（略有小改：生成 openid & 单点登录） =========

type SMSCode struct {
	Code        string    `json:"code"`
	CountryCode string    `json:"country_code"`
	Phone       string    `json:"phone"`
	ExpiresAt   time.Time `json:"expires_at"`
	Attempts    int       `json:"attempts"`
	IP          string    `json:"ip"`
}

func GenerateRedisKey(prefix, countryCode, phone string) string {
	return fmt.Sprintf("%s:%s%s", prefix, countryCode, phone)
}

func NormalizePhone(phone string) string {
	return strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, phone)
}

func IsValidPhone(phone string) bool {
	cleaned := NormalizePhone(phone)
	return len(cleaned) >= 8 && len(cleaned) <= 15
}

func IsValidCountryCode(countryCode string) bool {
	if len(countryCode) < 2 || len(countryCode) > 5 {
		return false
	}
	if countryCode[0] != '+' {
		return false
	}
	for _, c := range countryCode[1:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func StoreSMSCode(countryCode, phone, code, ip string, expiration time.Duration) error {
	rdb := database.GetRedis()
	normalizedPhone := NormalizePhone(phone)
	key := GenerateRedisKey("sms_code", countryCode, normalizedPhone)

	smsCode := SMSCode{
		Code:        code,
		CountryCode: countryCode,
		Phone:       normalizedPhone,
		ExpiresAt:   time.Now().Add(expiration),
		Attempts:    0,
		IP:          ip,
	}
	data, err := json.Marshal(smsCode)
	if err != nil {
		return err
	}
	if err := rdb.Set(context.Background(), key, data, expiration).Err(); err != nil {
		return err
	}
	rateKey := GenerateRedisKey("sms_rate_limit", countryCode, normalizedPhone)
	return rdb.Set(context.Background(), rateKey, "1", time.Minute).Err()
}

func ValidateSMSCode(countryCode, phone, code string) (bool, error) {
	rdb := database.GetRedis()
	normalizedPhone := NormalizePhone(phone)
	key := GenerateRedisKey("sms_code", countryCode, normalizedPhone)

	data, err := rdb.Get(context.Background(), key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return false, nil
		}
		return false, err
	}
	var smsCode SMSCode
	if err := json.Unmarshal(data, &smsCode); err != nil {
		return false, err
	}
	if time.Now().After(smsCode.ExpiresAt) {
		rdb.Del(context.Background(), key)
		return false, nil
	}
	return smsCode.Code == code, nil
}

func IsRateLimited(countryCode, phone, ip string) bool {
	rdb := database.GetRedis()
	normalizedPhone := NormalizePhone(phone)

	phoneKey := GenerateRedisKey("sms_rate_limit", countryCode, normalizedPhone)
	phoneExists, _ := rdb.Exists(context.Background(), phoneKey).Result()
	if phoneExists > 0 {
		return true
	}
	ipKey := "ip_rate_limit:" + ip
	ipCount, err := rdb.Get(context.Background(), ipKey).Int()
	if err == nil && ipCount >= 10 {
		return true
	}
	return false
}

func UpdateIPRequestCount(ip string) {
	rdb := database.GetRedis()
	ipKey := "ip_rate_limit:" + ip
	pipe := rdb.TxPipeline()
	pipe.Incr(context.Background(), ipKey)
	pipe.Expire(context.Background(), ipKey, time.Hour)
	pipe.Exec(context.Background())
}

func IsLoginAttemptLimited(countryCode, phone string) bool {
	rdb := database.GetRedis()
	key := GenerateRedisKey("login_attempts", countryCode, NormalizePhone(phone))
	attempts, err := rdb.Get(context.Background(), key).Int()
	if err != nil {
		return false
	}
	return attempts >= 5
}

func IncrementLoginAttempts(countryCode, phone string) {
	rdb := database.GetRedis()
	key := GenerateRedisKey("login_attempts", countryCode, NormalizePhone(phone))
	pipe := rdb.TxPipeline()
	pipe.Incr(context.Background(), key)
	pipe.Expire(context.Background(), key, 5*time.Minute)
	pipe.Exec(context.Background())
}

func ClearSMSCode(countryCode, phone string) {
	rdb := database.GetRedis()
	key := GenerateRedisKey("sms_code", countryCode, NormalizePhone(phone))
	rdb.Del(context.Background(), key)
}

func ClearLoginAttempts(countryCode, phone string) {
	rdb := database.GetRedis()
	key := GenerateRedisKey("login_attempts", countryCode, NormalizePhone(phone))
	rdb.Del(context.Background(), key)
}

func sendSMSHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req SMSRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if !IsValidPhone(req.Phone) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "手机号格式不正确"})
			return
		}
		if !IsValidCountryCode(req.CountryCode) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "国家代码格式不正确"})
			return
		}
		clientIP := c.ClientIP()
		if IsRateLimited(req.CountryCode, req.Phone, clientIP) {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "请求过于频繁，请稍后再试"})
			return
		}
		code := generateSMSCode()
		if err := StoreSMSCode(req.CountryCode, req.Phone, code, clientIP, 5*time.Minute); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "发送验证码失败"})
			return
		}
		UpdateIPRequestCount(clientIP)

		fullPhone := req.CountryCode + req.Phone
		go sendSMS(fullPhone, code)

		c.JSON(http.StatusOK, gin.H{"message": "验证码已发送", "expires_in": 300})
	}
}

func phoneLoginHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req PhoneLoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if !IsValidPhone(req.Phone) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "手机号格式不正确"})
			return
		}
		if !IsValidCountryCode(req.CountryCode) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "国家代码格式不正确"})
			return
		}
		if IsLoginAttemptLimited(req.CountryCode, req.Phone) {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "尝试次数过多，请稍后再试"})
			return
		}
		valid, err := ValidateSMSCode(req.CountryCode, req.Phone, req.Code)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "验证码验证失败"})
			return
		}
		if !valid {
			IncrementLoginAttempts(req.CountryCode, req.Phone)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "验证码错误或已过期"})
			return
		}
		user, err := findOrCreateUserByPhone(db, req.CountryCode, req.Phone)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "用户创建失败"})
			return
		}
		sessionID := uuid.NewString()
		if err := setCurrentSession(c, req.AppID, user.ID, sessionID, time.Hour*24*7); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "会话创建失败"})
			return
		}
		token, jti, err := generateJWT(*user, req.AppID, sessionID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "生成令牌失败"})
			return
		}
		ClearSMSCode(req.CountryCode, req.Phone)
		ClearLoginAttempts(req.CountryCode, req.Phone)

		c.JSON(http.StatusOK, gin.H{
			"message": "登录成功",
			"token":   token,
			"openid":  user.OpenID,
			"user": gin.H{
				"id":           user.ID,
				"username":     user.Username,
				"phone":        user.Phone,
				"country_code": user.CountryCode,
			},
			"jti": jti,
		})
	}
}

func findOrCreateUserByPhone(db *gorm.DB, countryCode, phone string) (*User, error) {
	normalizedPhone := NormalizePhone(phone)
	var user User
	if result := db.Where("country_code = ? AND phone = ?", countryCode, normalizedPhone).First(&user); result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			username := generateUsername(countryCode, normalizedPhone)
			user = User{
				OpenID:        uuid.NewString(),
				Username:      username,
				CountryCode:   countryCode,
				Phone:         normalizedPhone,
				PhoneVerified: true,
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
			}
			if result := db.Create(&user); result.Error != nil {
				return nil, result.Error
			}
			return &user, nil
		}
		return nil, result.Error
	}
	if !user.PhoneVerified {
		db.Model(&user).Update("phone_verified", true)
	}
	if user.OpenID == "" {
		db.Model(&user).Update("open_id", uuid.NewString())
	}
	return &user, nil
}

func generateSMSCode() string {
	rand.Seed(time.Now().UnixNano())
	return fmt.Sprintf("%06d", rand.Intn(1000000))
}

func generateUsername(countryCode, phone string) string {
	phone = NormalizePhone(phone)
	if len(phone) >= 6 {
		return "user_" + strings.TrimPrefix(countryCode, "+") + "_" + phone[len(phone)-6:]
	}
	return "user_" + strings.TrimPrefix(countryCode, "+") + "_" + phone
}

func sendSMS(phone, code string) {
	log.Printf("向手机号 %s 发送验证码: %s", phone, code)
}
