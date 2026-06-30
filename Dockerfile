FROM golang:1.26-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o minrouter .

FROM alpine:3.21

COPY --from=builder /app/minrouter /usr/local/bin/minrouter

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/minrouter"]
