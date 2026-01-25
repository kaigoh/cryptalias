# syntax=docker/dockerfile:1

FROM golang:1.24-alpine AS build
WORKDIR /src

RUN apk add --no-cache ca-certificates git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/cryptalias ./cmd/cryptalias

FROM alpine:3.20
WORKDIR /app

RUN apk add --no-cache ca-certificates && \
    adduser -D -H -u 10001 appuser

COPY --from=build /out/cryptalias /app/cryptalias

EXPOSE 8080
USER appuser

ENTRYPOINT ["/app/cryptalias"]
CMD ["/config/config.yml"]
