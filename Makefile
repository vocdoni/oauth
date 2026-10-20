# SPDX-License-Identifier: AGPL-3.0-only

IMAGE ?= vocdoni-oauth:dev
# htpasswd for the local password hash (bcrypt); pinned like the base image.
HTPASSWD_IMAGE ?= httpd:2.4-alpine@sha256:3440c39d8d6f54fa9ad2549e5a60c19ddd435faadc29c1ad28aa795f71888889

.PHONY: help image smoke add-client dev dev-down test test-go test-node

help:
	@echo "make image                          build $(IMAGE)"
	@echo "make smoke                          build and run the container smoke test"
	@echo "make add-client ID=<id> URL=<url>   register a tool (optional NAME=...)"
	@echo "make dev PASSWORD=<password, no quotes>  local provider on http://localhost:5556 (dev@vocdoni.org)"
	@echo "make dev-down                       stop it"
	@echo "make test                           Go and Node kit tests"

image:
	docker build -t $(IMAGE) .

smoke: image
	scripts/smoke.sh $(IMAGE)

add-client:
	@scripts/add-client.sh "$(ID)" "$(URL)" "$(or $(NAME),$(ID))"

dev:
	@test -n "$(PASSWORD)" || { echo "usage: make dev PASSWORD=<password for dev@vocdoni.org>"; exit 1; }
	DEV_PASSWORD_HASH="$$(docker run --rm $(HTPASSWD_IMAGE) htpasswd -nbBC 10 dev '$(PASSWORD)' | cut -d: -f2)" \
	  docker compose up --build

dev-down:
	docker compose down

test: test-go test-node

test-go:
	cd go && go test -race -count=1 ./...
	cd examples/go && go test -count=1 ./...

test-node:
	cd node && npm ci --no-audit --no-fund && npm run typecheck && npm test
