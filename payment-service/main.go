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
	models := []interface{}{&Payment{}}
	if err := database.AutoMigrateModels(db, models); err != nil {
		log.Fatal("数据库迁移失败:", err)
	}

	r := gin.Default()

	// 创建支付订单
	r.POST("/create", func(c *gin.Context) {
		var paymentData struct {
			UserID      uint    `json:"user_id" binding:"required"`
			Amount      float64 `json:"amount" binding:"required"`
			Currency    string  `json:"currency" binding:"required"`
			Description string  `json:"description"`
		}

		if err := c.ShouldBindJSON(&paymentData); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// 创建支付订单
		payment := Payment{
			UserID:      paymentData.UserID,
			Amount:      paymentData.Amount,
			Currency:    paymentData.Currency,
			Status:      "pending",
			Description: paymentData.Description,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		if result := db.Create(&payment); result.Error != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "创建支付订单失败"})
			return
		}

		// 这里应该调用第三方支付API（如Stripe、支付宝、微信支付）
		// 生成支付链接或二维码

		c.JSON(http.StatusOK, gin.H{
			"message":      "支付订单创建成功",
			"payment_id":   payment.ID,
			"payment_url":  "https://payment-gateway.com/pay/" + strconv.FormatUint(uint64(payment.ID), 10),
			"qr_code_url":  "https://payment-gateway.com/qr/" + strconv.FormatUint(uint64(payment.ID), 10),
			"payment_data": payment,
		})
	})

	// 查询支付状态
	r.GET("/:id/status", func(c *gin.Context) {
		paymentID, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "无效的支付ID"})
			return
		}

		var payment Payment
		if result := db.First(&payment, paymentID); result.Error != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "支付订单不存在"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"payment_id": payment.ID,
			"status":     payment.Status,
			"amount":     payment.Amount,
			"currency":   payment.Currency,
		})
	})

	// 支付回调处理（第三方支付平台调用）
	r.POST("/:id/callback", func(c *gin.Context) {
		paymentID, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "无效的支付ID"})
			return
		}

		var payment Payment
		if result := db.First(&payment, paymentID); result.Error != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "支付订单不存在"})
			return
		}

		// 解析回调数据，验证签名等
		// 这里应该根据第三方支付平台的回调数据更新支付状态

		payment.Status = "completed"
		payment.UpdatedAt = time.Now()
		db.Save(&payment)

		// 这里应该触发支付成功的事件，比如发放商品、增加用户余额等

		c.JSON(http.StatusOK, gin.H{
			"message": "支付回调处理成功",
			"status":  "ok",
		})
	})

	log.Println("支付服务启动在 :8083")
	r.Run(":8083")
}
