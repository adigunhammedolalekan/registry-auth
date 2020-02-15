FROM alpine:3.2
RUN apk update && apk add --no-cache ca-certificates
RUN apk add build-base
ADD . /app
WORKDIR /app
RUN chmod +x /app/example-auth
ENTRYPOINT [ "/app/example-auth" ]