package database

import (
	"log"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

// WaitForDB 等待数据库就绪并返回连接
func WaitForDB(dsn string, maxRetries int) (*gorm.DB, error) {
	var db *gorm.DB
	var err error

	for i := 0; i < maxRetries; i++ {
		db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
		if err != nil {
			log.Printf("无法连接数据库，重试中... (%d/%d)", i+1, maxRetries)
			time.Sleep(3 * time.Second)
			continue
		}

		// 测试连接是否有效
		sqlDB, err := db.DB()
		if err != nil {
			log.Printf("获取数据库实例失败，重试中... (%d/%d)", i+1, maxRetries)
			time.Sleep(3 * time.Second)
			continue
		}

		if err := sqlDB.Ping(); err != nil {
			log.Printf("数据库ping失败，重试中... (%d/%d)", i+1, maxRetries)
			time.Sleep(3 * time.Second)
			continue
		}

		log.Println("数据库连接成功")
		return db, nil
	}

	return nil, err
}
