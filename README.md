[![build](https://github.com/under-tension/magma/actions/workflows/build.yml/badge.svg)](https://github.com/under-tension/magma/actions/workflows/build.yml) [![cppcheck](https://github.com/under-tension/magma/actions/workflows/cppcheck.yml/badge.svg)](https://github.com/under-tension/magma/actions/workflows/cppcheck.yml) [![valgrind](https://github.com/under-tension/magma/actions/workflows/valgrind.yml/badge.svg)](https://github.com/under-tension/magma/actions/workflows/valgrind.yml) [![tests](https://github.com/under-tension/magma/actions/workflows/tests.yml/badge.svg)](https://github.com/under-tension/magma/actions/workflows/tests.yml) [![Coverage](https://sonarcloud.io/api/project_badges/measure?project=under-tension_magma&metric=coverage)](https://sonarcloud.io/summary/new_code?id=under-tension_magma)

## 🌋 MAGMA

Cryptographic library for working with the block width MAGMA aka GOST 34.12-2015

> [!WARNING]
> Not to be confused with the block cipher GOST 28147-89

## ✨ Features

#### Supported modes

- [x] Electronic Codebook (ECB)
- [x] Cipher Block Chaining (CBC)
- [x] Cipher Feedback (CFB)
- [x] Output Feedback (OFB)
- [x] Counter (CTR)
- [x] Message authentication code (MAC)

## 🚀 Get started

1) Cloning

```bash
git clone --recursive https://github.com/under-tension/magma.git magma
cd ./magma
```

2) Building

```bash
make
```

## 🧪 Testing

1) Build tests

```bash
make test
```

2) Run unit test

```bash
./bin/test
```