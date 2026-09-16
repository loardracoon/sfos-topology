BIN := sfos-topology

.PHONY: build test fmt run serve probe capture clean up down logs image rebuild

build:
	go build -o $(BIN) ./cmd/sfos-topology

test:
	go vet ./...
	go test ./...

fmt:
	gofmt -w .

# Reads every firewall in devices.json and writes graph.json.
run: build
	set -a; . ./lab.env; set +a; ./$(BIN) -config devices.json -out graph.json

# Same, then serves the viewer with the graph already loaded.
serve: build
	set -a; . ./lab.env; set +a; ./$(BIN) -config devices.json -serve 127.0.0.1:8080

# Connects to each appliance and prints its TLS fingerprint. Paste the value
# into pinSha256 in devices.json once you have confirmed it.
probe: build
	set -a; . ./lab.env; set +a; ./$(BIN) -config devices.json -probe

# Snapshots the raw API responses into captures/<label>/ for offline work.
capture:
	set -a; . ./lab.env; set +a; \
	./capture.sh 192.168.101.99:4444 "$$SFOS_TOKEN_FW101" captures/fw101; \
	./capture.sh 192.168.102.99:4444 "$$SFOS_TOKEN_FW102" captures/fw102; \
	./capture.sh 192.168.103.99:4444 "$$SFOS_TOKEN_FW103" captures/fw103

# ---- containers -----------------------------------------------------------
# Compose reads lab.env itself through env_file, so these targets do not source
# it. Works the same with podman-compose.

image:
	docker compose build

up:
	docker compose up -d --build
	@echo "viewer on http://127.0.0.1:8080"

# Use this after changing the Dockerfile or .dockerignore: a cached COPY layer
# would otherwise be reused and keep a stale build context.
rebuild:
	docker compose build --no-cache
	docker compose up -d
	@echo "viewer on http://127.0.0.1:8080"

down:
	docker compose down

logs:
	docker compose logs -f topology

clean:
	rm -f $(BIN) graph.json
