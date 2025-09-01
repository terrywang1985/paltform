package database

import (
	"log"

	"gorm.io/gorm"
)

// AutoMigrateModels 自动迁移所有指定的模型
func AutoMigrateModels(db *gorm.DB, models []interface{}) error {
	for _, model := range models {
		if err := db.AutoMigrate(model); err != nil {
			log.Printf("迁移模型失败: %v", err)
			return err
		}
	}
	log.Println("所有数据库模型迁移成功")
	return nil
}

// GetDBConfig 获取数据库配置
func GetDBConfig(host, user, password, dbName string) string {
	return user + ":" + password + "@tcp(" + host + ":3306)/" + dbName + "?charset=utf8mb4&parseTime=True&loc=Local"
}
