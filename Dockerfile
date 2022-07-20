FROM alpine:latest
RUN sed -i 's!https://dl-cdn.alpinelinux.org/!https://mirrors.tuna.tsinghua.edu.cn/!g' /etc/apk/repositories
RUN apk update \
    && apk add tzdata \
    && apk add --no-cache bash \
    && apk add curl \
    && apk add iptables \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
    && echo "Asia/Shanghai" > /etc/timezone
RUN mkdir -p /data
WORKDIR /data
RUN chmod -R a+rw /data
COPY ./bin/polaris_security /data/

RUN chmod +x /data/polaris_security

