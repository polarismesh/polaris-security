.PHONY: build image lint

build:
		CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -a -o ./bin/polaris_security main.go

image:
		CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -a -o ./bin/polaris_security main.go
		docker build  \
			--build-arg "HTTP_PROXY=${http_proxy}" \
			--build-arg "HTTPS_PROXY=${https_proxy}" \
			--build-arg "NO_PROXY=localhost,127.0.0.1" \
			--network host -t polarismesh/polaris-security .
format:
		gofumpt -l -w .
		golangci-lint run -c .golangci.yaml .
