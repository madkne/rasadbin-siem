mkdir -p build

CGO_ENABLED=1 go build \
  -ldflags "-X main.version=0.1.0" \
  -o build/rasadbin \
  ./cmd/app
