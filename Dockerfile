FROM golang:1.23-alpine as builder

WORKDIR /app

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -extldflags=-static" -o main .

FROM alpine:3

LABEL Author=Koalr(https://github.com/zema1)

# 安装 Chrome 和必要的依赖
RUN apk add --no-cache \
    chromium \
    chromium-chromedriver \
    nss \
    freetype \
    freetype-dev \
    harfbuzz \
    ca-certificates \
    ttf-freefont \
    nodejs \
    yarn

# 设置时区
RUN apk add --update tzdata && \
    cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    echo "Asia/Shanghai" > /etc/timezone && \
    apk del tzdata && \
    rm -rf /var/cache/apk/*

# 设置 Chrome 环境变量
ENV CHROME_BIN=/usr/bin/chromium-browser \
    CHROME_PATH=/usr/lib/chromium/

WORKDIR /app

COPY --from=builder /app/main /app/main

ENV DINGDING_ACCESS_TOKEN="" DINGDING_SECRET="" WECHATWORK_KEY="" BARK_URL="" INTERVAL=30m
ENTRYPOINT ["/app/main"]