FROM golang:1.24.4-alpine AS builder
WORKDIR /
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /honeypot
FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /honeypot /honeypot
ENTRYPOINT ["/honeypot"]
