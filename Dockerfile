FROM golang:1.22-alpine as builder


WORKDIR /app

#ENV GO111MODULE=on \
#    GOPROXY=https://goproxy.cn,direct

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -extldflags=-static" -o main .


FROM alpine:3

LABEL Author=Koalr(https://github.com/zema1)

RUN apk add --update tzdata && \
    cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    echo "Asia/Shanghai" > /etc/timezone && \
    apk del tzdata && \
    rm -rf /var/cache/apk/*

WORKDIR /app

COPY --from=builder /app/main /app/main

ENV DINGDING_ACCESS_TOKEN="" DINGDING_SECRET="" WECHATWORK_KEY="" BARK_URL="" INTERVAL=30m
ENTRYPOINT ["/app/main"]