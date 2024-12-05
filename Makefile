BUILD_DIR ?= build

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)/

.PHONY: build
build:
	cmake -S . -B $(BUILD_DIR)/ -DENABLE_TESTS=OFF
	cmake --build $(BUILD_DIR)/

.PHONY: test
test:
	cmake -S . -B $(BUILD_DIR)/ -DENABLE_TESTS=ON
	cmake --build $(BUILD_DIR)/
	LSAN_OPTIONS=detect_leaks=0 ctest --test-dir build/ --output-on-failure