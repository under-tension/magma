#ifndef TYPES_H
#define TYPES_H

typedef enum {
    MAGMA_SUCCESS               = 0,
    MAGMA_ERROR_NULL_POINTER    = 1,
    MAGMA_ERROR_INVALID_LENGTH  = 2,
    MAGMA_ERROR_IV_EMPTY        = 3,
    MAGMA_ERROR_INTERNAL        = 4
} MagmaResult;

#endif