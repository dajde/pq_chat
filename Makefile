TARGET = x86_64-unknown-linux-gnu
RELEASE = --release

RUSTFLAGS = -C target-feature=+crt-static

OUT_DIR = ./bin

build:
	@echo "Building for target: $(TARGET) with release settings: $(RELEASE)"
	RUSTFLAGS='$(RUSTFLAGS)' cargo build $(RELEASE) --target $(TARGET)
	@mkdir -p $(OUT_DIR)
	@cp target/$(TARGET)/release/client $(OUT_DIR)
	@cp target/$(TARGET)/release/server $(OUT_DIR)
	@cp target/$(TARGET)/release/keyserver $(OUT_DIR)

.PHONY: build
