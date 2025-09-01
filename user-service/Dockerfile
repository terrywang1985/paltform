FROM golang:1.19-alpine

# 设置工作目录
WORKDIR /workspace

# 复制整个项目到容器中
COPY . .

# 启用 Go workspace
RUN go work init
RUN go work use ./api-gateway
RUN go work use ./auth-service
RUN go work use ./user-service
RUN go work use ./payment-service
RUN go work use ./backstage-service
RUN go work use ./shared

# 切换到服务目录
WORKDIR /workspace/user-service

# 下载依赖
RUN go mod download

# 构建应用
RUN go build -o user-service .

EXPOSE 8082

CMD ["./user-service"]