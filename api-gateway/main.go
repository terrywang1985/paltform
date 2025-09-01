// api-gateway/main.go
package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	// 健康检查端点
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// 认证服务路由
	r.Any("/auth/*path", createProxy("http://auth-service:8081"))

	// 用户服务路由
	r.Any("/user/*path", createProxy("http://user-service:8082"))

	// 支付服务路由
	r.Any("/payment/*path", createProxy("http://payment-service:8083"))

	// 后台服务路由
	r.Any("/backstage/*path", createProxy("http://backstage-service:8084"))

	// 启动网关
	log.Println("API网关启动在 :8080")
	r.Run(":8080")
}

// 创建反向代理
func createProxy(target string) gin.HandlerFunc {
	return func(c *gin.Context) {
		remote, err := url.Parse(target)
		if err != nil {
			panic(err)
		}

		proxy := httputil.NewSingleHostReverseProxy(remote)
		proxy.Director = func(req *http.Request) {
			req.Header = c.Request.Header
			req.Host = remote.Host
			req.URL.Scheme = remote.Scheme
			req.URL.Host = remote.Host
			req.URL.Path = c.Param("path")
		}

		proxy.ServeHTTP(c.Writer, c.Request)
	}
}