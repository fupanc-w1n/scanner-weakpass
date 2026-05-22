# scanner-weakpass: 弱口令爆破 Pod 镜像
# SSH / MySQL / Redis 三类弱口令检测。GHA 默认 GOPROXY 可直接构建。
#
# Pod 运行时支持下列环境变量(K8s Deployment 可通过 env 字段覆盖):
#   DAST_CONFIG       默认 /app/config/config.json   ConfigMap 挂载点
#   DAST_DB_USER      默认 root                       MySQL 账号
#   DAST_DB_PASS      代码默认 root                   MySQL 密码,可通过 ENV 覆盖
#   DAST_DB_NAME      默认 dast                       MySQL 数据库
#   DAST_REDIS_PASS   默认 redis                      Redis 密码(为空表示无密码)
# MySQL/Redis 地址、端口由 ConfigMap 中的 scheduler.internal_ip / mysql_port / redis_port 决定。

FROM golang:1.25-alpine AS builder
WORKDIR /src
# ENV GOPROXY=https://goproxy.cn,direct
COPY . .
RUN go mod init scanner-weakpass \
 && go mod tidy \
 && CGO_ENABLED=0 GOOS=linux go build -o /out/scanner-weakpass .

FROM alpine:latest
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /out/scanner-weakpass /app/scanner-weakpass
ENV DAST_CONFIG=/app/config/config.json \
    DAST_DB_USER=root \
    DAST_DB_PASS=fupanC@123 \
    DAST_DB_NAME=dast \
    DAST_REDIS_PASS=redis \
    TZ=Asia/Shanghai
ENTRYPOINT ["/app/scanner-weakpass"]
