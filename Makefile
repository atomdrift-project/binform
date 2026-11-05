# binform Makefile: build, test, lint and install the library and its tools.
# Uses only constructs common to GNU make and BSD make.

# Command-line tools built from the tools/ workspace member.
BINARIES = binform binform-ab

# Scrub make's jobserver from cargo's environment, so build scripts that
# spawn their own `make` don't inherit a malformed MAKEFLAGS.
CARGO = env -u MAKEFLAGS -u MAKELEVEL -u MFLAGS cargo

# Where cargo writes its output: $CARGO_TARGET_DIR when set, else `target`.
CARGO_TARGET_DIR ?= target

.PHONY: all build test lint fix fmt install clean help

all: build

help:
	@echo "binform Makefile"
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build    - Build the workspace in debug mode (default)"
	@echo "  test     - Run all tests"
	@echo "  lint     - Run rustfmt --check, clippy and rustdoc with warnings denied"
	@echo "  fix      - Auto-fix clippy lints, then format with rustfmt"
	@echo "  fmt      - Format code with rustfmt"
	@echo "  install  - Install $(BINARIES) to the first writeable PATH dir"
	@echo "  clean    - Remove build artifacts"

build:
	$(CARGO) build --workspace

test:
	$(CARGO) test --workspace --all-features

# Mirrors the CI lint job.
lint:
	$(CARGO) fmt --all --check
	$(CARGO) clippy --workspace --all-targets --all-features -- -D warnings
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc --no-deps --all-features

# Run fmt last so it tidies any code clippy rewrote.
fix:
	$(CARGO) clippy --fix --workspace --all-targets --all-features --allow-dirty --allow-staged
	$(CARGO) fmt --all

fmt:
	$(CARGO) fmt --all

# Installing via a temporary file and rename replaces a running binary
# safely and avoids macOS's stale code-signature cache.
install:
	$(CARGO) build --release -p binform-tools
	@set -e; \
	if echo "$$PATH" | tr ':' '\n' | grep -qx "$$HOME/.cargo/bin" && [ -d "$$HOME/.cargo/bin" ]; then \
		dir="$$HOME/.cargo/bin"; \
	elif [ -d "$$HOME/bin" ] && [ -w "$$HOME/bin" ]; then \
		dir="$$HOME/bin"; \
	elif [ -d "$$HOME/.local/bin" ] && [ -w "$$HOME/.local/bin" ]; then \
		dir="$$HOME/.local/bin"; \
	elif [ -w /usr/local/bin ]; then \
		dir="/usr/local/bin"; \
	else \
		mkdir -p "$$HOME/.cargo/bin"; \
		dir="$$HOME/.cargo/bin"; \
	fi; \
	for bin in $(BINARIES); do \
		install -m 755 "$(CARGO_TARGET_DIR)/release/$$bin" "$$dir/$$bin.new"; \
		mv -f "$$dir/$$bin.new" "$$dir/$$bin"; \
		echo "✓ Installed $$dir/$$bin"; \
	done

clean:
	$(CARGO) clean
