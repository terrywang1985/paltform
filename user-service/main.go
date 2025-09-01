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

type User struct {
	ID        uint   `gorm:"primaryKey"`
	Username  string `gorm:"uniqueIndex"`
	Email     string `gorm:"uniqueIndex"`
	FirstName string
	LastName  string
	Avatar    string
	CreatedAt time.Time
	UpdatedAt time.Time
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

	// 获取用户信息
	r.GET("/:id", func(c *gin.Context) {
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

		c.JSON(http.StatusOK, gin.H{
			"user": user,
		})
	})

	// 更新用户信息
	r.PUT("/:id", func(c *gin.Context) {
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
			FirstName string `json:"first_name"`
			LastName  string `json:"last_name"`
			Avatar    string `json:"avatar"`
		}

		if err := c.ShouldBindJSON(&updateData); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// 更新用户信息
		if updateData.FirstName != "" {
			user.FirstName = updateData.FirstName
		}
		if updateData.LastName != "" {
			user.LastName = updateData.LastName
		}
		if updateData.Avatar != "" {
			user.Avatar = updateData.Avatar
		}

		user.UpdatedAt = time.Now()
		db.Save(&user)

		c.JSON(http.StatusOK, gin.H{
			"message": "用户信息更新成功",
			"user":    user,
		})
	})

	log.Println("用户服务启动在 :8082")
	r.Run(":8082")
}
