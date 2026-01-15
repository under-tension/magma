CC          ?= gcc
CFLAGS      ?= -Wall -Wextra -std=c11 -g -O0
CTESTFLAGS  ?= -fPIC -fprofile-arcs -ftest-coverage -fno-inline
INCLUDES    := -I./include

# Libs for test
CRITERION_DIR ?= ./third_party/criterion
CRITERION_LIB  = $(CRITERION_DIR)/build/src
CRITERION_INC  = $(CRITERION_DIR)/include

LIB_SRC := \
	./src/core/crypt.c \
	./src/core/keys.c \
	./src/core/utils.c \
	./src/modes/ctr.c \
	./src/modes/ofb.c \
	./src/modes/cbc.c \
	./src/modes/cfb.c \
	./src/modes/ecb.c \
	./src/modes/mac.c

TEST_SRC := \
	./test/core/test_crypt.c \
	./test/core/test_keys.c \
	./test/core/test_utils.c \
	./test/modes/test_ctr.c \
	./test/modes/test_ofb.c \
	./test/modes/test_cbc.c \
	./test/modes/test_cfb.c \
	./test/modes/test_ecb.c \
	./test/modes/test_mac.c

TEST_BIN := ./test.out

.PHONY: test-build test clean

test-build: $(TEST_BIN)

$(TEST_BIN): $(LIB_SRC) $(TEST_SRC) | check-criterion
	gcc $(CFLAGS) $(CTESTFLAGS) $(INCLUDES) -I$(CRITERION_INC) \
		$(TEST_SRC) $(LIB_SRC) \
		-L$(CRITERION_LIB) -lcriterion -lpthread -lm \
		-o $@

clean-coverage:
	find . -name "*.gcda" -delete

printcov:
	gcovr --root . --exclude 'test|third_party'

# Check isset Criterion
check-criterion:
	@if [ ! -f "$(CRITERION_LIB)/libcriterion.a" ] && [ ! -f "$(CRITERION_LIB)/libcriterion.so" ]; then \
		echo "❌ Criterion not found in $(CRITERION_LIB)"; \
		echo "👉 Please build Criterion first (e.g., run: cd $(CRITERION_DIR) && meson build && ninja -C build)"; \
		exit 1; \
	fi

test: test-build
	@./test.out

clean:
	rm -f $(TEST_BIN)