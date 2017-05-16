/************************ fnv-private.h ************************/
/****************** See RFC NNNN for details *******************/
/* Copyright (c) 2016 IETF Trust and the persons identified as
 * authors of the code.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * *  Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * *  Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * *  Neither the name of Internet Society, IETF or IETF Trust, nor the
 *    names of specific contributors, may be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/* https://tools.ietf.org/id/draft-eastlake-fnv-12.txt */

#ifndef _FNV_H_
#define _FNV_H_

/*
 *      Six FNV-1a hashes are defined with these sizes:
 *              FNV32          32 bits, 4 bytes
 *              FNV64          64 bits, 8 bytes
 *              FNV128         128 bits, 16 bytes
 *              FNV256         256 bits, 32 bytes
 *              FNV512         512 bits, 64 bytes
 *              FNV1024        1024 bits, 128 bytes
 */

/* Private stuff used by this implementation of the FNV
 * (Fowler, Noll, Vo) non-cryptographic hash function FNV-1a.
 * External callers don't need to know any of this.  */

enum {  /* State value bases for context->Computed */
    FNVinited = 22,
    FNVcomputed = 76,
    FNVemptied = 220,
    FNVclobber = 122 /* known bad value for testing */
};

/* Deltas to assure distinct state values for different lengths */
enum {
   FNV32state = 1,
   FNV64state = 3,
   FNV128state = 5,
   FNV256state = 7,
   FNV512state = 11,
   FNV1024state = 13
};

/***************************** FNV64.h ******************************/
/******************* See RFC NNNN for details. **********************/
/*
 * Copyright (c) 2016 IETF Trust and the persons identified as
 * authors of the code.  All rights reserved.
 * See fnv-private.h for terms of use and redistribution.
 */

#define _FNV64_H_

/*
 *  Description:
 *      This file provides headers for the 64-bit version of the FNV-1a
 *      non-cryptographic hash algorithm.
 */

#include <stdint.h>
#define FNV64size (64/8)

/* If you do not have the ISO standard stdint.h header file, then you
 * must typedef the following types:
 *
 *    type             meaning
 *  uint64_t        unsigned 64 bit integer (ifdef FNV_64bitIntegers)
 *  uint32_t        unsigned 32 bit integer
 *  uint16_t        unsigned 16 bit integer
 *  uint8_t         unsigned 8 bit integer (i.e., unsigned char)
 */

#ifndef _FNV_ErrCodes_
#define _FNV_ErrCodes_
/*********************************************************************
 *  All FNV functions provided return as integer as follows:
 *       0 -> success
 *      >0 -> error as listed below
 */
enum {    /* success and errors */
    fnvSuccess = 0,
    fnvNull,            /* Null pointer parameter */
    fnvStateError,      /* called Input after Result, etc. */
    fnvBadParam         /* passed a bad parameter */
};
#endif /* _FNV_ErrCodes_ */

/*
 *  This structure holds context information for an FNV64 hash
 */
#ifdef FNV_64bitIntegers
    /* version if 64 bit integers supported */

typedef struct FNV64context_s {
        int Computed;  /* state */
        uint64_t Hash;
} FNV64context;

#else
    /* version if 64 bit integers NOT supported */

typedef struct FNV64context_s {
        int Computed;  /* state */
        uint16_t Hash[FNV64size/2];
} FNV64context;

#endif /* FNV_64bitIntegers */

/*
 *  Function Prototypes
 *    FNV64string: hash a zero terminated string not including
 *                 the terminating zero
 *    FNV64block: FNV64 hash a specified length byte vector
 *    FNV64init: initializes an FNV64 context
 *    FNV64initBasis: initializes an FNV64 context with a
 *                    provided basis
 *    FNV64blockin: hash in a specified length byte vector
 *    FNV64stringin: hash in a zero terminated string not
 *                   incluing the zero
 *    FNV64result: returns the hash value
 *
 *    Hash is returned as a 64-bit integer if supported, otherwise
 *         as a vector of 8-bit integers
 */

#ifdef __cplusplus
extern "C" {
#endif

/* FNV64 */
extern int FNV64init ( FNV64context * const );
extern int FNV64blockin ( FNV64context * const,
                          const void * in,
                          long int length );
extern int FNV64stringin ( FNV64context * const,
                           const char * in );

#ifdef FNV_64bitIntegers
  extern int FNV64string ( const char *in,
                           uint64_t * const out );
  extern int FNV64block ( const void *in,
                          long int length,
                          uint64_t * const out );
  extern int FNV64initBasis ( FNV64context * const,
                            uint64_t basis );
  extern int FNV64result ( FNV64context * const,
                           uint64_t * const out );
#else
  extern int FNV64string ( const char *in,
                           uint8_t out[FNV64size] );
  extern int FNV64block ( const void *in,
                          long int length,
                          uint8_t out[FNV64size] );
  extern int FNV64initBasis ( FNV64context * const,
                            const uint8_t basis[FNV64size] );
  extern int FNV64result ( FNV64context * const,
                           uint8_t out[FNV64size] );
#endif /* FNV_64bitIntegers */

#ifdef __cplusplus
}
#endif

#endif
