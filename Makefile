PROJ_NAME = magma

CC          ?= gcc
CFLAGS      ?= -Wall -Wextra -Werror -pedantic -std=c2x -g
CTESTFLAGS  ?= -Wall -Wextra -Werror -pedantic -std=c2x -fPIC --coverage
INCLUDES    := -I./include
THIRD_PARTY_DIR := ./third_party
LIB_DIR := ./lib
BIN_DIR := ./bin
BUILD_DIR := ./build
SRC_DIR := ./src
INCLUDE_DIRS := ./include
LDFLAGS := -fPIC -shared -lc

TEST_SRC_DIR := ./test
TEST_SRC = $(shell find $(TEST_SRC_DIR) -name '*.c')
TEST_BIN = ./bin/test

CRITERION_DIR ?= $(THIRD_PARTY_DIR)/criterion
CRITERION_LIB  = $(CRITERION_DIR)/build/src
CRITERION_INC  = $(CRITERION_DIR)/include

TARGET = $(LIB_DIR)/lib$(PROJ_NAME).so
TARGET_STATIC = $(LIB_DIR)/lib$(PROJ_NAME).a

SRCS := $(shell find $(SRC_DIR) -name '*.c')
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

.PHONY: test build_test clean docs clean-coverage printcov check-criterion

all: $(TARGET) $(TARGET_STATIC)

$(TARGET): $(OBJS) | $(LIB_DIR)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

$(TARGET_STATIC): $(OBJS) | $(LIB_DIR)
	$(AR) rcs $@ $^

$(LIB_DIR):
	mkdir -p $(LIB_DIR)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)/src/core $(BUILD_DIR)/src/modes

$(BUILD_DIR)/%.o: ./src/%.c | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

build_test = $(TEST_BIN)

test: check-bin-dir build_test

check-bin-dir:
	mkdir -p $(BIN_DIR)

build_test: $(SRCS) $(TEST_SRC) | check-criterion
	gcc $(CTESTFLAGS) $(INCLUDES) -I$(CRITERION_INC) \
		$(TEST_SRC) $(SRCS) \
		-L$(CRITERION_LIB) -lcriterion -lpthread -lm \
		-o $(TEST_BIN)

clean-coverage:
	find . -name "*.gcda" -delete -o -name "*.gcno" -delete

printcov:
	gcovr --root ./ --object-directory ./bin --exclude 'test|third_party'

# Check isset Criterion
check-criterion:
	@if [ ! -f "$(CRITERION_LIB)/libcriterion.a" ] && [ ! -f "$(CRITERION_LIB)/libcriterion.so" ]; then \
		echo "❌ Criterion not found in $(CRITERION_LIB)"; \
		echo "👉 Please build Criterion first (e.g., run: cd $(CRITERION_DIR) && meson build && ninja -C build)"; \
		exit 1; \
	fi

docs:
	doxygen Doxyfile

lint:
	cppcheck \
	--enable=all \
	--std=c2x \
	--platform=unix32 \
	--platform=unix64 \
	--platform=win32A \
	--platform=win32W \
	--platform=win64 \
	--error-exitcode=1 \
	--check-level=exhaustive \
	--disable=unusedFunction \
	--suppress=missingIncludeSystem \
    --suppress=checkersReport \
	$(INCLUDES) $(SRC_DIR) $(INCLUDE_DIRS)

valgrind:
	valgrind --leak-check=full --error-exitcode=1 --errors-for-leak-kinds=all $(TEST_BIN)

clean: clean-coverage
	rm -f $(OBJS) $(TARGET) $(TARGET_STATIC)
	rm -f $(TEST_BIN)