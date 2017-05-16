/* draft 12 */
/******************** See RFC NNNN for details **********************/
/* Copyright (c) 2016 IETF Trust and the persons identified as
 * authors of the code.  All rights reserved.
 * See fnv-private.h for terms of use and redistribution.
*/

/* This file implements the FNV (Fowler, Noll, Vo) non-cryptographic
 * hash function FNV-1a for 64-bit hashes.
*/

#ifndef _FNV64_C_
#define _FNV64_C_

#include "fnv.h"

/********************************************************************
 *        START VERSION FOR WHEN YOU HAVE 64 BIT ARITHMETIC         *
 ********************************************************************/
#ifdef FNV_64bitIntegers

/* 64 bit FNV_prime = 2^40 + 2^8 + 0xb3 */
#define FNV64prime 0x00000100000001B3
#define FNV64basis 0xCBF29CE484222325

/* FNV64 hash a null terminated string  (64 bit)
 ********************************************************************/
int FNV64string ( const char *in, uint64_t * const out )
{
uint64_t    temp;
uint8_t     ch;

if ( in && out )
    {
    temp = FNV64basis;
    while ( (ch = *in++) )
        temp = FNV64prime * ( temp ^ ch );
#ifdef FNV_BigEndian
    FNV64reverse ( out, temp );
#else
    *out = temp;
#endif
    return fnvSuccess;
    }
return fnvNull; /* Null input pointer */
}   /* end FNV64string */

/* FNV64 hash a counted block  (64 bit)
 ********************************************************************/
int FNV64block ( const void *vin,
                 long int length,
                 uint64_t * const out )
{
const uint8_t *in = (const uint8_t*)vin;
uint64_t    temp;

if ( in && out )
    {
    if ( length < 0 )
        return fnvBadParam;
    for ( temp = FNV64basis; length > 0; length-- )
        temp = FNV64prime * ( temp ^ *in++ );
#ifdef FNV_BigEndian
    FNV64reverse ( out, temp );
#else
    *out = temp;
#endif
    return fnvSuccess;
    }
return fnvNull; /* Null input pointer */
}   /* end FNV64block */

#ifdef FNV_BigEndian

/* Store a Big Endian result back as Little Endian
 ***************************************************************/
static void FNV64reverse ( uint64_t *out, uint64_t hash )
{
uint64_t    temp;
int         i;

temp = hash & 0xFF;
for ( i = FNV64size - 1; i > 0; i-- )
    {
    hash >>= 8;
    temp = ( temp << 8 ) + ( hash & 0xFF );
    }
*out = temp;
}   /* end FNV64reverse */

#endif /* FNV_BigEndian */


/********************************************************************
 *         Set of init, input, and output functions below           *
 *         to incrementally compute FNV64                           *
 ********************************************************************/

/* initialize context  (64 bit)
 ********************************************************************/

int FNV64init ( FNV64context * const ctx )
{
return FNV64initBasis ( ctx, FNV64basis );
}       /* end FNV64init */

/* initialize context with a provided basis  (64 bit)
 ********************************************************************/
int FNV64initBasis ( FNV64context * const ctx, uint64_t basis )
{
if ( ctx )
    {
    ctx->Hash = basis;
    ctx->Computed = FNVinited+FNV64state;
    return fnvSuccess;
    }
return fnvNull;
}       /* end FNV64initBasis */

/* hash in a counted block  (64 bit)
 ********************************************************************/
int FNV64blockin ( FNV64context * const ctx,
                   const void *vin,
                   long int length )
{
const uint8_t *in = (const uint8_t*)vin;
uint64_t    temp;

if ( ctx && in )
    {
    if ( length < 0 )
        return fnvBadParam;
    switch ( ctx->Computed )
        {
        case FNVinited+FNV64state:
            ctx->Computed = FNVcomputed+FNV64state;
        case FNVcomputed+FNV64state:
            break;
        default:
            return fnvStateError;
        }
    for ( temp = ctx->Hash; length > 0; length-- )
        temp = FNV64prime * ( temp ^ *in++ );
    ctx->Hash = temp;
    return fnvSuccess;
    }
return fnvNull;
}   /* end FNV64input */

/* hash in a zero terminated string not including the zero (64 bit)
 ********************************************************************/

int FNV64stringin ( FNV64context * const ctx,
                    const char *in )
{
uint64_t        temp;
uint8_t         ch;

if ( ctx && in )
    {
    switch ( ctx->Computed )
        {
        case FNVinited+FNV64state:
            ctx->Computed = FNVcomputed+FNV64state;
        case FNVcomputed+FNV64state:
            break;
        default:
             return fnvStateError;
         }
    temp = ctx->Hash;
    while ( (ch = *in++) )
        temp = FNV64prime * ( temp ^ ch );
    ctx->Hash = temp;
    return fnvSuccess;
    }
return fnvNull;
}   /* end FNV64stringin */

/* return hash  (64 bit)
 ********************************************************************/
int FNV64result ( FNV64context * const ctx,
                  uint64_t * const out )
{
if ( ctx && out )
    {
    if ( ctx->Computed != FNVcomputed+FNV64state )
        return fnvStateError;
    ctx->Computed = FNVemptied+FNV64state;
#ifdef FNV_BigEndian
    FNV64reverse ( out, ctx->Hash );
#else
    *out = ctx->Hash;
#endif
    ctx->Hash = 0;
    return fnvSuccess;
    }
return fnvNull;
}   /* end FNV64result */

/******************************************************************
 *        END VERSION FOR WHEN YOU HAVE 64 BIT ARITHMETIC         *
 ******************************************************************/

#else    /*  FNV_64bitIntegers */
/******************************************************************
 *     START VERSION FOR WHEN YOU ONLY HAVE 32-BIT ARITHMETIC     *
 ******************************************************************/

/* 64 bit FNV_prime = 2^40 + 2^8 + 0xb3 */
/* #define FNV64prime 0x00000100000001B3 */
#define FNV64primeX 0x01B3
#define FNV64shift 8

/* #define FNV64basis 0xCBF29CE484222325 */
#define FNV64basis0 0xCBF2
#define FNV64basis1 0x9CE4
#define FNV64basis2 0x8422
#define FNV64basis3 0x2325

/* FNV64 hash a null terminated string  (32 bit)
 ********************************************************************/
int FNV64string ( const char *in, uint8_t out[FNV64size] )
{
FNV64context     ctx;
int              err;

 if ( ( err = FNV64init (&ctx) ) != fnvSuccess )
    return err;
 if ( ( err = FNV64stringin (&ctx, in) ) != fnvSuccess )
    return err;
return FNV64result (&ctx, out);
}   /* end FNV64string */

/* FNV64 hash a counted block  (32 bit)
 ********************************************************************/
int FNV64block ( const void *in,
                 long int length,
                 uint8_t out[FNV64size] )
{
FNV64context     ctx;
int              err;

 if ( ( err = FNV64init (&ctx) ) != fnvSuccess )
    return err;
 if ( ( err = FNV64blockin (&ctx, in, length) ) != fnvSuccess )
    return err;
return FNV64result (&ctx, out);
}   /* end FNV64block */


/********************************************************************
 *         Set of init, input, and output functions below           *
 *         to incrementally compute FNV64                           *
 ********************************************************************/

/* initialize context  (32 bit)
 ********************************************************************/
int FNV64init ( FNV64context * const ctx )
{
if ( ctx )
    {
    ctx->Hash[0] = FNV64basis0;
    ctx->Hash[1] = FNV64basis1;
    ctx->Hash[2] = FNV64basis2;
    ctx->Hash[3] = FNV64basis3;
    ctx->Computed = FNVinited+FNV64state;
    return fnvSuccess;
    }
return fnvNull;
}   /* end FNV64init */

/* initialize context  (32 bit)
 ********************************************************************/
int FNV64initBasis ( FNV64context * const ctx,
                     const uint8_t basis[FNV64size] )
{
if ( ctx )
    {
#ifdef FNV_BigEndian
    ctx->Hash[0] = basis[1] + ( basis[0]<<8 );
    ctx->Hash[1] = basis[3] + ( basis[2]<<8 );
    ctx->Hash[2] = basis[5] + ( basis[4]<<8 );
    ctx->Hash[3] = basis[7] + ( basis[6]<<8 );
#else
    ctx->Hash[0] = basis[0] + ( basis[1]<<8 );
    ctx->Hash[1] = basis[2] + ( basis[3]<<8 );
    ctx->Hash[2] = basis[4] + ( basis[5]<<8 );
    ctx->Hash[3] = basis[6] + ( basis[7]<<8 );
#endif
    ctx->Computed = FNVinited+FNV64state;
    return fnvSuccess;
    }
return fnvNull;
}   /* end FNV64initBasis */

/* hash in a counted block  (32 bit)
 ********************************************************************/
int FNV64blockin ( FNV64context * const ctx,
                   const void *vin,
                   long int length )
{
const uint8_t *in = (const uint8_t*)vin;
uint32_t   temp[FNV64size/2];
uint32_t   temp2[2];
int        i;

if ( ctx && in )
    {
    if ( length < 0 )
        return fnvBadParam;
    switch ( ctx->Computed )
        {
        case FNVinited+FNV64state:
            ctx->Computed = FNVcomputed+FNV64state;
        case FNVcomputed+FNV64state:
            break;
        default:
            return fnvStateError;
        }
    for ( i=0; i<FNV64size/2; ++i )
         temp[i] = ctx->Hash[i];
    for ( ; length > 0; length-- )
        {
        /* temp = FNV64prime * ( temp ^ *in++ ); */
        temp2[1] = temp[3] << FNV64shift;
        temp2[0] = temp[2] << FNV64shift;
        temp[3] = FNV64primeX * ( temp[3] ^ *in++ );
        temp[2] *= FNV64primeX;
        temp[1] = temp[1] * FNV64primeX + temp2[1];
        temp[0] = temp[0] * FNV64primeX + temp2[0];
        temp[2] += temp[3] >> 16;
        temp[3] &= 0xFFFF;
        temp[1] += temp[2] >> 16;
        temp[2] &= 0xFFFF;
        temp[0] += temp[1] >> 16;
        temp[1] &= 0xFFFF;
        }
    for ( i=0; i<FNV64size/2; ++i )
        ctx->Hash[i] = temp[i];
    return fnvSuccess;
    }
return fnvNull;
}   /* end FNV64blockin */

/* hash in a string  (32 bit)
 ********************************************************************/
int FNV64stringin ( FNV64context * const ctx,
                    const char *in )
{
uint32_t   temp[FNV64size/2];
uint32_t   temp2[2];
int        i;
uint8_t    ch;

if ( ctx && in )
    {
    switch ( ctx->Computed )
        {
        case FNVinited+FNV64state:
            ctx->Computed = FNVcomputed+FNV64state;
        case FNVcomputed+FNV64state:
            break;
        default:
             return fnvStateError;
         }
    for ( i=0; i<FNV64size/2; ++i )
         temp[i] = ctx->Hash[i];
    while ( ( ch = (uint8_t)*in++ ) != 0)
        {
        /* temp = FNV64prime * ( temp ^ ch ); */
        temp2[1] = temp[3] << FNV64shift;
        temp2[0] = temp[2] << FNV64shift;
        temp[3] = FNV64primeX * ( temp[3] ^ *in++ );
        temp[2] *= FNV64primeX;
        temp[1] = temp[1] * FNV64primeX + temp2[1];
        temp[0] = temp[0] * FNV64primeX + temp2[0];
        temp[2] += temp[3] >> 16;
        temp[3] &= 0xFFFF;
        temp[1] += temp[2] >> 16;
        temp[2] &= 0xFFFF;
        temp[0] += temp[1] >> 16;
        temp[1] &= 0xFFFF;
        }
    for ( i=0; i<FNV64size/2; ++i )
        ctx->Hash[i] = temp[i];
    return fnvSuccess;
    }
return fnvNull;
}   /* end FNV64stringin */

/* return hash  (32 bit)
 ********************************************************************/
int FNV64result ( FNV64context * const ctx,
                  uint8_t out[FNV64size] )
{
int    i;

if ( ctx && out )
    {
    if ( ctx->Computed != FNVcomputed+FNV64state )
        return fnvStateError;
    for ( i=0; i<FNV64size/2; ++i )
        {
#ifdef FNV_BigEndian
        out[7-2*i] = ctx->Hash[i];
        out[6-2*i] = ctx->Hash[i] >> 8;
#else
        out[2*i] = ctx->Hash[i];
        out[2*i+1] = ctx->Hash[i] >> 8;
#endif
        ctx -> Hash[i] = 0;
        }
    ctx->Computed = FNVemptied+FNV64state;
    return fnvSuccess;
    }
return fnvNull;
}   /* end FNV64result */

#endif    /*  FNV_64bitIntegers */
/********************************************************************
 *        END VERSION FOR WHEN YOU ONLY HAVE 32-BIT ARITHMETIC      *
 ********************************************************************/

#endif    /* _FNV64_C_ */
