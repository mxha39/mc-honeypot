# Build stage
FROM golang:1.24.4-alpine AS builder

WORKDIR /

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /honeypot

FROM scratch

COPY --from=builder /honeypot /honeypot

ENTRYPOINT ["/honeypot"]
