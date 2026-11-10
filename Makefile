# The same targets run locally and in CI: every step a developer would run is one of these, and
# the workflows call them rather than repeating the commands.
#
#   make venv            Python dependencies, installed from hash-locked files
#   make images          the router and node images (make image-router: the router only)
#   make unit            generator unit tests (no containers)
#   make gate1           Gate 1: Conftest, loaded nftables, vtysh, Batfish (Batfish must be running)
#   make test            Gate 2: render, deploy, test, collect evidence, destroy
#   make test FAULT=F08  the same with one planted fault
#   make lock            re-generate the hashed lock files from requirements*.in (needs uv)
#
# Needs Linux with Docker, containerlab and sudo for the lab targets.

VENV     ?= .venv
PY       := $(VENV)/bin/python
RENDER   ?= build/lab
RESULTS  ?= results
EVIDENCE ?= evidence
CONFTEST ?= conftest
FAULT    ?=

.PHONY: help venv venv-batfish images image-router render unit gate1 deploy gate2 evidence destroy test lock

help:
	@sed -n '1,14p' Makefile

venv:
	python3 -m venv $(VENV)
	$(PY) -m pip install -q --require-hashes -r requirements.txt

venv-batfish:
	python3 -m venv $(VENV)
	$(PY) -m pip install -q --require-hashes -r requirements-batfish.txt

images: image-router
	docker build -q -t packetproof/node:dev images/node

image-router:
	docker build -q -t packetproof/router:dev -t packetproof/router:w1 images/router

render:
	$(PY) -m packetproof render $(if $(FAULT),--fault $(FAULT)) --out $(RENDER)

unit:
	$(PY) -m pytest -q -p no:cacheprovider tests/unit

gate1: render
	$(PY) scripts/gate1.py --render $(RENDER) --out $(RESULTS)/gate1.json --conftest $(CONFTEST)

deploy:
	$(PY) -m packetproof deploy --render $(RENDER)

gate2:
	PP_RENDER=$(RENDER) $(PY) -m pytest tests/live -v -p no:cacheprovider --junitxml $(RESULTS)/gate2.xml

evidence:
	$(PY) -m packetproof evidence --render $(RENDER) --out $(EVIDENCE)

destroy:
	$(PY) -m packetproof destroy --render $(RENDER)

# Gate 2 end to end. Evidence is collected and the lab destroyed whatever the tests say, and the
# target still fails if they failed.
test: render
	@rc=0; \
	$(MAKE) --no-print-directory deploy || rc=$$?; \
	[ $$rc -eq 0 ] && { $(MAKE) --no-print-directory gate2 || rc=$$?; }; \
	$(MAKE) --no-print-directory evidence || true; \
	$(MAKE) --no-print-directory destroy || true; \
	exit $$rc

lock:
	uv pip compile requirements.in --python-version 3.14 --python-platform x86_64-manylinux_2_28 --generate-hashes --no-header -q -o requirements.txt
	uv pip compile requirements-batfish.in --python-version 3.14 --python-platform x86_64-manylinux_2_28 --generate-hashes --no-header -q -o requirements-batfish.txt
