FROM golang:1.10-alpine AS builder
MAINTAINER "Matt Zahorik <matt.zahorik@gmail.com>"

RUN apk update && \
    apk add git build-base && \
    mkdir -p "$GOPATH/src/github.com/mzahorik/f5-ingress-ctlr"

ADD . "$GOPATH/src/github.com/mzahorik/f5-ingress-ctlr"

RUN cd "$GOPATH/src/github.com/mzahorik/f5-ingress-ctlr" && \
    export VERSION=`cat release.txt` && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a --ldflags="-X main.version=$VERSION -s -w -extldflags \"-static\"" -o /f5-ingress-ctlr


FROM scratch

COPY --from=builder /f5-ingress-ctlr /f5-ingress-ctlr

ENTRYPOINT ["/f5-ingress-ctlr"]
