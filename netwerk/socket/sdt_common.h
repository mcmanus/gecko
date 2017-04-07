/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

#ifndef SDT_COMMON
#define SDT_COMMON

#ifdef  __cplusplus
extern "C" {
#endif

#include "nspr.h"

#if 1
#define DEV_ABORT(x) do { abort(); } while (0)
#else
#define DEV_ABORT(x) do { } while (0)
#endif

int32_t
sdt_useRecv(PRFileDesc *fd, void *aBuf, int32_t aAmount);

int32_t
sdt_notImplemented(PRFileDesc *fd, void *aBuf, int32_t aAmount,
                   int flags, PRNetAddr *addr, PRIntervalTime to);

int32_t
sdt_notImplemented2(PRFileDesc *aFD, const void *aBuf, int32_t aAmount,
                    int flags, PRIntervalTime to);

int32_t
sdt_notImplemented3(PRFileDesc *aFD, const void *aBuf, int32_t aAmount,
                    int flags, const PRNetAddr* aAddr, PRIntervalTime to);

#ifdef  __cplusplus
}
#endif

#endif // SDT_COMMON
