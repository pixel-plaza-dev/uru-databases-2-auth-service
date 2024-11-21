FROM golang:1.23.2-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download && go mod verify

COPY . .

RUN go build -v -o /bin/server .

FROM alpine:latest AS server

WORKDIR /app

COPY --from=builder /bin/server /server

EXPOSE 8080

ENTRYPOINT ["/server", "-m=prod"]