FROM golang:latest AS builder
WORKDIR /workspace
ENV GO111MODULE on
ENV GOOS linux
ENV GOARCH amd64
ENV CGO_ENABLED 0
COPY . .
RUN go build -o /workspace/app -a -ldflags '-w -s' /workspace/main.go

FROM scratch
ENV TZ Asia/Bangkok
ADD https://golang.org/lib/time/zoneinfo.zip /usr/local/lib/time/
ADD https://curl.haxx.se/ca/cacert.pem /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /workspace/app /app
EXPOSE 1323
ENTRYPOINT ["/app"]