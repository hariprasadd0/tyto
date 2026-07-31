.PHONY: all generate build vet drift-check docker-build docker-smoke clean

BPF_ARTIFACTS := src/userspace/tyto_bpfel.go src/userspace/tyto_bpfeb.go \
	src/userspace/tyto_bpfel.o src/userspace/tyto_bpfeb.o

all: build

generate:
	cd src/userspace && go generate

build: generate
	cd src/userspace && go build -o tyto .

vet:
	cd src/userspace && go vet ./...

drift-check: generate
	git diff --exit-code -- $(BPF_ARTIFACTS)

docker-build:
	docker build -t tyto .

docker-smoke: docker-build
	@sudo ip link add tyto-smoke0 type dummy 2>/dev/null || true
	@docker rm -f tyto-smoke >/dev/null 2>&1 || true
	docker run -d --rm --privileged --network host --name tyto-smoke tyto tyto-smoke0
	@echo "Waiting for XDP attach..."
	@for i in $$(seq 1 15); do \
		if docker logs tyto-smoke 2>&1 | grep -q "Attached XDP program"; then \
			echo "XDP attach OK"; break; fi; \
		sleep 1; \
	done
	@docker logs tyto-smoke 2>&1 | grep -q "Attached XDP program"
	@sleep 2
	docker logs tyto-smoke 2>&1 | grep -q "\[STATS\]"
	@echo "SMOKE TEST PASSED"
	@docker stop tyto-smoke >/dev/null
	@sudo ip link del tyto-smoke0

clean:
	rm -f src/userspace/tyto
