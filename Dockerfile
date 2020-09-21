FROM golang:latest as build

RUN mkdir /app
WORKDIR /app
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
RUN go build -o letmein cmd/letmein/main.go
RUN go build -o migrate cmd/migrate/main.go

FROM debian:buster-slim
WORKDIR /app
COPY --from=build /app/letmein .
COPY --from=build /app/migrate .
RUN mkdir -p server/templates
RUN mkdir -p server/static/css
RUN mkdir -p db/migrations
COPY server/templates ./server/templates
COPY server/static/css ./server/static/css
COPY db/migrations ./db/migrations
RUN apt update
RUN apt install -y ca-certificates
CMD ["./letmein"]
