.PHONY: default all test build fmt clean

default: build

all: test build

test:
	cargo test --locked --package qasset-registry

build:
	cargo build --locked --package qasset-registry --target wasm32v1-none --release

fmt:
	cargo fmt --all

clean:
	cargo clean
