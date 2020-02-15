#!/bin/bash
NEW_UUID=$(cat /dev/urandom | LC_CTYPE=C tr -dc 'a-zA-Z0-9' | fold -w 8 | head -n 1)
export GOOS=linux && go build -o example-auth main.go
docker build -t "example-auth" .
docker tag example-auth localhost:5004/example-auth:${NEW_UUID}
docker push localhost:5004/example-auth:${NEW_UUID}