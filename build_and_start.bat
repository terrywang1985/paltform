
go work init
go work use ./api-gateway
go work use ./auth-service
go work use ./user-service
go work use ./payment-service
go work use ./backstage-service
go work use ./shared

cd api-gateway && go mod tidy && cd ..
cd auth-service && go mod tidy && cd ..
cd user-service && go mod tidy && cd ..
cd payment-service && go mod tidy && cd ..
cd backstage-service && go mod tidy && cd ..
cd api-gateway && go mod tidy && cd ..
cd shared && go mod tidy && cd ..

docker-compose up -d --build