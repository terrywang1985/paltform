# platform
user platform

#启动
build_and_start.bat


1. 查看所有容器的日志
bash
# 查看所有容器的实时日志
docker-compose logs -f

# 查看所有容器的日志（不跟随）
docker-compose logs

# 查看最后 N 行日志
docker-compose logs --tail=100
2. 查看特定容器的日志
bash
# 查看认证服务的日志
docker-compose logs auth-service

# 查看认证服务的实时日志
docker-compose logs -f auth-service

# 查看用户服务的日志
docker-compose logs user-service

# 查看支付服务的日志
docker-compose logs payment-service

# 查看后台服务的日志
docker-compose logs backstage-service

# 查看MySQL的日志
docker-compose logs mysql

# 查看Redis的日志
docker-compose logs redis
3. 使用 Docker 命令查看日志
如果您更喜欢使用原生的 Docker 命令，也可以使用：

bash
# 查看特定容器的日志
docker logs ds-paltform-auth-service-1

# 查看实时日志
docker logs -f ds-paltform-auth-service-1

# 查看最后100行日志
docker logs --tail=100 ds-paltform-auth-service-1

# 查看特定时间之后的日志
docker logs --since 10m ds-paltform-auth-service-1  # 最近10分钟
4. 查看特定时间段的日志
bash
# 查看最近10分钟的日志
docker logs --since 10m ds-paltform-auth-service-1

# 查看指定时间之后的日志
docker logs --since 2025-09-01T10:00:00 ds-paltform-auth-service-1

# 查看指定时间范围内的日志
docker logs --since 2025-09-01T10:00:00 --until 2025-09-01T11:00:00 ds-paltform-auth-service-1
5. 日志筛选和搜索
您还可以结合其他工具（如 grep）来筛选日志：

bash
# 筛选包含"error"的日志
docker-compose logs auth-service | grep -i error

# 实时监控错误日志
docker-compose logs -f auth-service | grep -i error

# 查看特定请求的日志
docker-compose logs auth-service | grep "POST /auth/login"
6. 查看容器内进程
除了日志，您还可以查看容器内运行的进程：

bash
# 查看认证服务容器内的进程
docker top ds-paltform-auth-service-1

# 查看所有容器的资源使用情况
docker stats
7. 进入容器查看
如果需要更深入的调试，可以进入容器内部：

bash
# 进入认证服务容器
docker exec -it ds-paltform-auth-service-1 sh

# 进入MySQL容器
docker exec -it ds-paltform-mysql-1 mysql -uuser -ppassword platform

# 进入Redis容器
docker exec -it ds-paltform-redis-1 redis-cli
8. 日志驱动和配置
如果您需要更复杂的日志管理，可以在 docker-compose.yml 中配置日志驱动：

yaml
services:
  auth-service:
    image: auth-service
    logging:
      driver: "json-file"
      options:
        max-size: "200k"
        max-file: "10"
