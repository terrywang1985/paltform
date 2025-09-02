package main

import (
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"shared/database"
)

// 使用与 auth-service 一致的 User 模型
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

// 内部认证中间件（与 auth-service 使用相同的共享密钥）
func internalAuthMiddleware() gin.HandlerFunc {
	internalSharedToken := os.Getenv("SHARED_INTERNAL_TOKEN")

	return func(c *gin.Context) {
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

	// 获取用户信息（通过ID）- 需要内部认证
	r.GET("/id/:id", internalAuthMiddleware(), func(c *gin.Context) {
		userID, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "无效的用户ID"})
			return
		}

		var user User
		if result := db.First(&user, userID); result.Error != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
			return
		}

		// 不返回敏感信息
		c.JSON(http.StatusOK, gin.H{
			"user": gin.H{
				"id":           user.ID,
				"openid":       user.OpenID,
				"username":     user.Username,
				"email":        user.Email,
				"country_code": user.CountryCode,
				"phone":        user.Phone,
				"first_name":   user.FirstName,
				"last_name":    user.LastName,
				"avatar":       user.Avatar,
				"created_at":   user.CreatedAt,
				"updated_at":   user.UpdatedAt,
			},
		})
	})

	// 获取用户信息（通过OpenID）- 需要内部认证
	r.GET("/openid/:openid", internalAuthMiddleware(), func(c *gin.Context) {
		openID := c.Param("openid")

		var user User
		if result := db.Where("open_id = ?", openID).First(&user); result.Error != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
			return
		}

		// 不返回敏感信息
		c.JSON(http.StatusOK, gin.H{
			"user": gin.H{
				"id":           user.ID,
				"openid":       user.OpenID,
				"username":     user.Username,
				"email":        user.Email,
				"country_code": user.CountryCode,
				"phone":        user.Phone,
				"first_name":   user.FirstName,
				"last_name":    user.LastName,
				"avatar":       user.Avatar,
				"created_at":   user.CreatedAt,
				"updated_at":   user.UpdatedAt,
			},
		})
	})

	// 批量获取用户信息 - 需要内部认证
	r.POST("/batch", internalAuthMiddleware(), func(c *gin.Context) {
		var request struct {
			UserIDs []uint   `json:"user_ids"`
			OpenIDs []string `json:"openids"`
		}

		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var users []User
		query := db.Select("id, open_id, username, email, country_code, phone, first_name, last_name, avatar, created_at, updated_at")

		if len(request.UserIDs) > 0 {
			query = query.Where("id IN ?", request.UserIDs)
		}

		if len(request.OpenIDs) > 0 {
			if len(request.UserIDs) > 0 {
				query = query.Or("open_id IN ?", request.OpenIDs)
			} else {
				query = query.Where("open_id IN ?", request.OpenIDs)
			}
		}

		if result := query.Find(&users); result.Error != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "查询用户失败"})
			return
		}

		// 转换为不包含敏感信息的响应格式
		var response []gin.H
		for _, user := range users {
			response = append(response, gin.H{
				"id":           user.ID,
				"openid":       user.OpenID,
				"username":     user.Username,
				"email":        user.Email,
				"country_code": user.CountryCode,
				"phone":        user.Phone,
				"first_name":   user.FirstName,
				"last_name":    user.LastName,
				"avatar":       user.Avatar,
				"created_at":   user.CreatedAt,
				"updated_at":   user.UpdatedAt,
			})
		}

		c.JSON(http.StatusOK, gin.H{
			"users": response,
		})
	})

	// 更新用户信息 - 需要内部认证
	r.PUT("/:id", internalAuthMiddleware(), func(c *gin.Context) {
		userID, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "无效的用户ID"})
			return
		}

		var user User
		if result := db.First(&user, userID); result.Error != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
			return
		}

		var updateData struct {
			FirstName   *string `json:"first_name"`
			LastName    *string `json:"last_name"`
			Avatar      *string `json:"avatar"`
			Email       *string `json:"email" binding:"omitempty,email"`
			Phone       *string `json:"phone"`
			CountryCode *string `json:"country_code"`
		}

		if err := c.ShouldBindJSON(&updateData); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// 更新用户信息
		if updateData.FirstName != nil {
			user.FirstName = *updateData.FirstName
		}
		if updateData.LastName != nil {
			user.LastName = *updateData.LastName
		}
		if updateData.Avatar != nil {
			user.Avatar = *updateData.Avatar
		}
		if updateData.Email != nil {
			// 检查邮箱是否已被其他用户使用
			var existingUser User
			if result := db.Where("email = ? AND id != ?", *updateData.Email, userID).First(&existingUser); result.Error == nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "邮箱已被其他用户使用"})
				return
			}
			user.Email = *updateData.Email
		}
		if updateData.Phone != nil {
			user.Phone = *updateData.Phone
		}
		if updateData.CountryCode != nil {
			user.CountryCode = *updateData.CountryCode
		}

		user.UpdatedAt = time.Now()
		if result := db.Save(&user); result.Error != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "更新用户信息失败"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "用户信息更新成功",
			"user": gin.H{
				"id":           user.ID,
				"openid":       user.OpenID,
				"username":     user.Username,
				"email":        user.Email,
				"country_code": user.CountryCode,
				"phone":        user.Phone,
				"first_name":   user.FirstName,
				"last_name":    user.LastName,
				"avatar":       user.Avatar,
				"updated_at":   user.UpdatedAt,
			},
		})
	})

	// 健康检查端点（不需要认证）
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
			"time":   time.Now().Format(time.RFC3339),
		})
	})

	log.Println("用户服务启动在 :8082")
	r.Run(":8082")
}
