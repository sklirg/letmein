FROM golang:latest as build

RUN mkdir /app
WORKDIR /app
COPY . .
RUN go build -o letmein cmd/letmein/main.go

FROM debian:buster-slim
COPY --from=build /app/letmein .
RUN mkdir -p server/templates
COPY --from=build /app/server/templates ./server/templates
CMD ["./letmein"]
