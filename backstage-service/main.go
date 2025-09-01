// 带路径的文件名
// backstage-service/main.go
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

type Payment struct {
	ID          uint    `gorm:"primaryKey"`
	UserID      uint    `gorm:"index"`
	Amount      float64 `gorm:"type:decimal(10,2)"`
	Currency    string
	Status      string `gorm:"type:ENUM('pending', 'completed', 'failed')"`
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type StatsRequest struct {
	StartDate string `form:"start_date"`
	EndDate   string `form:"end_date"`
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

	r := gin.Default()

	// 获取用户统计
	r.GET("/users/stats", func(c *gin.Context) {
		var req StatsRequest
		if err := c.ShouldBindQuery(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// 解析日期
		var startDate, endDate time.Time
		if req.StartDate != "" {
			startDate, _ = time.Parse("2006-01-02", req.StartDate)
		} else {
			startDate = time.Now().AddDate(0, 0, -30) // 默认最近30天
		}

		if req.EndDate != "" {
			endDate, _ = time.Parse("2006-01-02", req.EndDate)
		} else {
			endDate = time.Now()
		}

		// 总用户数
		var totalUsers int64
		db.Model(&User{}).Count(&totalUsers)

		// 新增用户数
		var newUsers int64
		db.Model(&User{}).Where("created_at BETWEEN ? AND ?", startDate, endDate).Count(&newUsers)

		// 每日注册用户数
		var dailyRegistrations []struct {
			Date  string `gorm:"column:date"`
			Count int    `gorm:"column:count"`
		}

		db.Raw(`
			SELECT DATE(created_at) as date, COUNT(*) as count 
			FROM users 
			WHERE created_at BETWEEN ? AND ? 
			GROUP BY DATE(created_at)
			ORDER BY date
		`, startDate, endDate).Scan(&dailyRegistrations)

		c.JSON(http.StatusOK, gin.H{
			"total_users":         totalUsers,
			"new_users":           newUsers,
			"daily_registrations": dailyRegistrations,
			"start_date":          startDate.Format("2006-01-02"),
			"end_date":            endDate.Format("2006-01-02"),
		})
	})

	// 获取支付统计
	r.GET("/payments/stats", func(c *gin.Context) {
		var req StatsRequest
		if err := c.ShouldBindQuery(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// 解析日期
		var startDate, endDate time.Time
		if req.StartDate != "" {
			startDate, _ = time.Parse("2006-01-02", req.StartDate)
		} else {
			startDate = time.Now().AddDate(0, 0, -30) // 默认最近30天
		}

		if req.EndDate != "" {
			endDate, _ = time.Parse("2006-01-02", req.EndDate)
		} else {
			endDate = time.Now()
		}

		// 总支付金额
		var totalRevenue struct {
			TotalAmount float64 `gorm:"column:total_amount"`
		}
		db.Raw(`
			SELECT SUM(amount) as total_amount 
			FROM payments 
			WHERE status = 'completed' AND created_at BETWEEN ? AND ?
		`, startDate, endDate).Scan(&totalRevenue)

		// 支付成功数
		var successfulPayments int64
		db.Model(&Payment{}).Where("status = 'completed' AND created_at BETWEEN ? AND ?", startDate, endDate).Count(&successfulPayments)

		// 每日收入
		var dailyRevenue []struct {
			Date  string  `gorm:"column:date"`
			Total float64 `gorm:"column:total"`
		}

		db.Raw(`
			SELECT DATE(created_at) as date, SUM(amount) as total 
			FROM payments 
			WHERE status = 'completed' AND created_at BETWEEN ? AND ? 
			GROUP BY DATE(created_at)
			ORDER BY date
		`, startDate, endDate).Scan(&dailyRevenue)

		c.JSON(http.StatusOK, gin.H{
			"total_revenue":       totalRevenue.TotalAmount,
			"successful_payments": successfulPayments,
			"daily_revenue":       dailyRevenue,
			"start_date":          startDate.Format("2006-01-02"),
			"end_date":            endDate.Format("2006-01-02"),
		})
	})

	// 获取用户列表
	r.GET("/users", func(c *gin.Context) {
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
		offset := (page - 1) * limit

		var users []User
		var total int64

		db.Model(&User{}).Count(&total)
		db.Order("created_at DESC").Offset(offset).Limit(limit).Find(&users)

		c.JSON(http.StatusOK, gin.H{
			"users": users,
			"pagination": gin.H{
				"page":  page,
				"limit": limit,
				"total": total,
				"pages": (int(total) + limit - 1) / limit,
			},
		})
	})

	// 获取支付记录列表
	r.GET("/payments", func(c *gin.Context) {
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
		offset := (page - 1) * limit

		var payments []Payment
		var total int64

		db.Model(&Payment{}).Count(&total)
		db.Order("created_at DESC").Offset(offset).Limit(limit).Find(&payments)

		c.JSON(http.StatusOK, gin.H{
			"payments": payments,
			"pagination": gin.H{
				"page":  page,
				"limit": limit,
				"total": total,
				"pages": (int(total) + limit - 1) / limit,
			},
		})
	})

	log.Println("后台服务启动在 :8084")
	r.Run(":8084")
}
