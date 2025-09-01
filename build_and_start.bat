cd auth-service && go mod tidy && cd ..
cd user-service && go mod tidy && cd ..
cd payment-service && go mod tidy && cd ..
cd backstage-service && go mod tidy && cd ..
cd api-gateway && go mod tidy && cd ..

docker-compose up -d --build