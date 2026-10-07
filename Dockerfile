FROM golang:1.25-alpine AS builder

WORKDIR /src

COPY go.mod ./
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/api ./cmd/api

FROM alpine:3.22

RUN addgroup -S app && adduser -S -G app app

WORKDIR /app
COPY --from=builder /out/api /app/api

USER app
EXPOSE 8080

ENTRYPOINT ["/app/api"]
