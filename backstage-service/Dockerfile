FROM golang:1.19-alpine

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o backstage-service .

EXPOSE 8084

CMD ["./backstage-service"]