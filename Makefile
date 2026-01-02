# test-build:
# 	gcc -o ./test.out \
# 	./test/keys.c \
# 	./test/core.c \
# 	./test/utils.c \
# 	./test/modes.c \
# 	./src/utils.c \
# 	./src/keys.c \
# 	./src/core.c \
# 	./src/modes.c \
# 	-L ./lib/criterion/build/src -lcriterion


CC          ?= gcc
CFLAGS      ?= -Wall -Wextra -std=c11 -g -O0
INCLUDES    := -I./include

# Libs for test
CRITERION_DIR ?= ./lib/criterion
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
	./src/modes/imit.c


TEST_SRC := \
	./test/core/crypt.c \
	./test/core/keys.c \
	./test/core/utils.c \
	./test/modes/ctr.c \
	./test/modes/ofb.c \
	./test/modes/cbc.c \
	./test/modes/cfb.c \
	./test/modes/ecb.c \
	./test/modes/imit.c

TEST_BIN := ./test.out

.PHONY: test-build test clean

test-build: $(TEST_BIN)

$(TEST_BIN): $(LIB_SRC) $(TEST_SRC) | check-criterion
	$(CC) $(CFLAGS) $(INCLUDES) -I$(CRITERION_INC) \
		$(TEST_SRC) $(LIB_SRC) \
		-L$(CRITERION_LIB) -lcriterion -lpthread -lm \
		-o $@

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