.PHONY: proto test

proto:
	protoc \
	  --go_out=. --go_opt=paths=source_relative \
	  --go-grpc_out=. --go-grpc_opt=paths=source_relative \
	  proto/vault/v1/vault.proto

test:
	go test ./...
	cd client-ts && npm test
