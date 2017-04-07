/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

#ifndef SDTUPPERLAYER

#define SDTUPPERLAYER

#include "nsASocketHandler.h"
#include "nsSocketTransportService2.h"
#include "mozilla/RefPtr.h"
#include "sdt.h"

namespace mozilla {
namespace net {

PRFileDesc *sdt_createSDTSocket(PRFileDesc *aFd);

class SDTUpper final : public nsASocketHandler {
public:
  NS_DECL_THREADSAFE_ISUPPORTS

  SDTUpper(PRFileDesc *aFd);
  bool HasData();
  bool SocketWritable();
  int32_t ReadData(void *aBuf, int32_t aAmount, int aFlags);
  int32_t WriteData(const void *aBuf, int32_t aAmount);
  void SetLocal(bool aLocal);
  PRFileDesc *GetLowerFd() { return mFd; }
  nsresult AttachSocket();
  bool IsAttached() { return mAttached; }
  void SetUpperFDDetached();
  bool IsError() { return mError; }
  PRInt16 GetPollError() { return mPollError; }

  // nsASocketHandler methods:
  void OnSocketReady(PRFileDesc *, int16_t outFlags) override;
  void OnSocketDetached(PRFileDesc *) override;
  void IsLocal(bool *aIsLocal) override;
  uint64_t ByteCountSent() override { return mByteWriteCount; }
  uint64_t ByteCountReceived() override { return mByteReadCount; }

private:
  ~SDTUpper() {}

  PRFileDesc *mFd;
  bool mIsLocal;
  RefPtr<nsSocketTransportService> mSocketTransportService;
  bool mAttached;
  bool mUpperFDDetached;
  uint64_t   mByteReadCount;
  uint64_t   mByteWriteCount;
  PRErrorCode mError;
  PRInt16 mPollError;
};

PRFileDesc * sdt_createSDTSocket(PRFileDesc *aFd);

} // namespace mozilla::net
} // namespace mozilla

#endif //SDTUPPERLAYER
