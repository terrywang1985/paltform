FROM golang:1.19-alpine

WORKDIR /app

# 复制go.mod和go.sum文件
COPY go.mod go.sum ./
RUN go mod download

# 复制源代码
COPY . .

# 构建应用
RUN go build -o auth-service .

EXPOSE 8081

CMD ["./auth-service"]