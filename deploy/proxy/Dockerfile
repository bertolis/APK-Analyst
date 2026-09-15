# Allow-list forward proxy (tinyproxy). Denies everything by default; only the
# hosts in `filter` are permitted, and only CONNECT to 443 (HTTPS).
FROM alpine:3.20

RUN apk add --no-cache tinyproxy

COPY tinyproxy.conf /etc/tinyproxy/tinyproxy.conf
COPY filter /etc/tinyproxy/filter

EXPOSE 8888
CMD ["tinyproxy", "-d", "-c", "/etc/tinyproxy/tinyproxy.conf"]
