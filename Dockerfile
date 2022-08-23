FROM golang:1.19-alpine AS builder
RUN apk add --no-cache \
    make \
    gcc musl-dev
WORKDIR /go/src
COPY . /go/src
RUN make build

FROM alpine
COPY --from=builder /go/src/bin/scas ./
ENTRYPOINT ["./scas"]
