FROM golang:1.19-alpine as builder

LABEL Author=Koalr(https://github.com/zema1)

WORKDIR /app

ENV GO111MODULE=on \
    GOPROXY=https://goproxy.cn,direct

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -extldflags=-static" -o main .


FROM alpine:3

WORKDIR /app

COPY --from=builder /app/main /app/main

ENV DINGDING_ACCESS_TOKEN="" DINGDING_SECRET="" WECHATWORK_KEY="" INTERVAL=30m
ENTRYPOINT ["/app/main"]