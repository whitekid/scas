TARGET=bin/scas
SRC=$(shell find . -type f -name '*.go' -not -path '*_test.go' -not -path './vendor/*')
LDFLAGS ?= "-s -w"
BUILD_FLAGS ?= -v -ldflags ${LDFLAGS}
TEST_FLAGS ?= -v

GIT_COMMIT ?= $(shell git rev-parse HEAD)
GIT_SHA ?= $(shell git rev-parse --short HEAD)
GIT_BRANCH ?= $(shell git rev-parse --abbrev-ref HEAD)
GIT_TAG ?= $(shell git describe --tags --always)
GIT_DIRTY ?= $(shell test -n "`git status --porcelain`" && echo "dirty" || echo "clean")
VER_BUILD_TIME ?= $(shell date +%Y-%m-%dT%H:%M:%S%z)

.PHONY: all clean test dep tidy swag

all: $(TARGET)
bin/%: ${SRC}
	@mkdir -p $(dir $@)
	@#echo "build $@ $(@F)" 
	go build -o bin/ ${BUILD_FLAGS} ./cmd/...

build: $(TARGET)

# $(TARGET): $(SRC)
# 	@go build -o bin/ ${BUILD_FLAGS} ./cmd/...

clean:
	rm -f ${TARGET}

test:
	@go test ${TEST_FLAGS} ./...

# update modules & tidy
dep:
	@rm -f go.mod go.sum
	@go mod init scas

	@$(MAKE) tidy

tidy:
	@go mod tidy -v

docker:
	docker build --pull --rm -t scas -f Dockerfile .

pack:
	pack build scas --buildpack paketo-buildpacks/go --builder paketobuildpacks/builder:base

swag:
	@swag init -d swagger api/v1alpha1/v1alpha1.go
