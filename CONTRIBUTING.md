##  🤝 Contributing

## 🎯 Project objectives

Create a reliable cryptographic library with good documentation and easy to understand. If possible, without dynamic memory allocation.

#### 📜 Rules

1) Support code documentation by using Doxygen comments in header files.

2) Maintain unit testing coverage, don't forget to make changes or write new tests.

3) Make sure that your changes are checked in the ci pipelines.

4) All project proposals and bug information are processed in the github issue.

## 🔗 Dependencies for local development

- GCC >=12.2.0
- Cppcheck >=2.19.0
- Valgrind >=3.19.0
- gcovr >=5.2
- Doxygen >=1.16.1
- Meson >=1.7.0
- Ninja >=1.11.1
- Cmake >=3.25.1
- libgit2-dev
- libffi-dev
- pkg-config

## 🏗️ Architecture

#### Project structure

```
magma/
├── bin/                    # Build results
├── build/                  # Intermediate files involved in building the project
├── docs/                   # Pages and assets for documentation
├── include/                # Header files
├── lib/                    # Static and dynamic libraries
├── src/                    # Source code
├── test/                   # Unit tests
└── third_party/            # External auxiliary tools that do not affect the build
```

## Make commands

1) Run linter

```bash
make lint
```

2) Run valgrind

```bash
make valgrind
```

3) Check test coverage

    1) Start building test

    ```bash
    make test
    ```

    2) Run the tests

    ```bash
    ./bin/test
    ```

    3) Print test coverage

    ```bash
    make printcov
    ```