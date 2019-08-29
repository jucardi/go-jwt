all: check deps test build

check: format vet

format:
	@echo "formatting files..."
	@go get golang.org/x/tools/cmd/goimports
	@go get github.com/jucardi/goimports-blank-rm
	@goimports-blank-rm . 1>/dev/null 2>/dev/null
	@goimports -w -l . 1>/dev/null
	@gofmt -s -w -l . 1>/dev/null

vet:
	@echo "vetting..."
	@go vet ./...

protoc:
	@echo "generating protobuf..."
	@go get github.com/golang/protobuf/protoc-gen-go
	@go get github.com/jucardi/protoc-go-inject-tag
	@protoc -I=$(PWD)/proto --go_out=$(PWD) $(PWD)/proto/*.proto
	@protoc-go-inject-tag --input "$(PWD)/*.pb.go" --cleanup -x yaml -x gorm -x bson

deps: protoc
	@echo "installing dependencies..."
	@go get -t ./...

test-deps:
	@echo "installing test dependencies..."
	@go get github.com/smartystreets/goconvey/convey
	@go get gopkg.in/h2non/gock.v1
	@go get github.com/stretchr/testify/assert
	@go get github.com/axw/gocov/...
	@go get github.com/AlekSi/gocov-xml
	@go get gopkg.in/matm/v1/gocov-html

test: test-deps
	@echo "running test coverage..."
	@mkdir -p test-artifacts/coverage
	@gocov test ./... -v > test-artifacts/gocov.json
	@cat test-artifacts/gocov.json | gocov report
	@cat test-artifacts/gocov.json | gocov-xml > test-artifacts/coverage/coverage.xml
	@cat test-artifacts/gocov.json | gocov-html > test-artifacts/coverage/coverage.html