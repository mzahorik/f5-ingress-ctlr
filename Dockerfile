FROM golang:1.10-alpine AS builder
MAINTAINER "Matt Zahorik <matt.zahorik@gmail.com>"

RUN apk update && \
    apk add git build-base dep && \
    mkdir -p "$GOPATH/src/github.com/mzahorik/f5-ctlr"

ADD . "$GOPATH/src/github.com/mzahorik/f5-ctlr"

RUN cd "$GOPATH/src/github.com/mzahorik/f5-ctlr" && \
    dep init && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a --ldflags='-extldflags "-static"' -o /f5-ctlr

FROM busybox:1.28
RUN mkdir -p /bin

COPY --from=builder /f5-ctlr /bin/f5-ctlr

ENTRYPOINT ["/bin/f5-ctlr"]
