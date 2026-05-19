FROM alpine:3.20
RUN apk add --no-cache curl ca-certificates python3 tzdata
COPY watchdog.sh /watchdog.sh
RUN chmod +x /watchdog.sh
ENV TZ=America/New_York
ENTRYPOINT ["/watchdog.sh"]
