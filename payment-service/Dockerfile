FROM golang:1.19-alpine

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o payment-service .

EXPOSE 8083

CMD ["./payment-service"]