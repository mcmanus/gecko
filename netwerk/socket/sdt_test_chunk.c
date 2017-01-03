
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "sdt_interface_tests.h"
#include <assert.h>

struct aDataChunk_t;

int main()
{
  struct aDataChunk_t *chunk = CreateChunk(DATA_CHUNK, 20, 0, 0);
  ChunkAddRef(chunk);

  LogRanges(chunk);
  AddNewRange(chunk, 0, 20);
  LogRanges(chunk);
  assert(NumNotSentRanges(chunk) == 1);
  assert(NumUnackedRanges(chunk) == 0);
  LogRanges(chunk);
  assert(HasNotSentRange(chunk, 0, 20));
  LogRanges(chunk);

  SomeDataSentFromChunk(chunk, 2);
  assert(NumNotSentRanges(chunk) == 1);
  assert(NumUnackedRanges(chunk) == 1);
  assert(HasNotSentRange(chunk, 2, 20));
  assert(HasUnackedRange(chunk, 0, 2));

  SomeDataSentFromChunk(chunk, 4);
  assert(NumNotSentRanges(chunk) == 1);
  assert(NumUnackedRanges(chunk) == 1);
  assert(HasNotSentRange(chunk, 6, 20));
  assert(HasUnackedRange(chunk, 0, 6));

  SomeDataSentFromChunk(chunk, 3);
  assert(NumNotSentRanges(chunk) == 1);
  assert(NumUnackedRanges(chunk) == 1);
  assert(HasNotSentRange(chunk, 9, 20));
  assert(HasUnackedRange(chunk, 0, 9));

  SomeDataLostFromChunk(chunk, 2, 6);
  assert(NumNotSentRanges(chunk) == 2);
  assert(NumUnackedRanges(chunk) == 2);
  assert(HasNotSentRange(chunk, 2, 6));
  assert(HasNotSentRange(chunk, 9, 20));
  assert(HasUnackedRange(chunk, 0, 2));
  assert(HasUnackedRange(chunk, 6, 9));


  SomeDataLostFromChunk(chunk, 0, 20);
  assert(NumNotSentRanges(chunk) == 1);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 0, 20));

  AckSomeDataSentFromChunk(chunk, 0, 20);
  assert(NumNotSentRanges(chunk) == 0);
  assert(NumUnackedRanges(chunk) == 0);

  AddNewRange(chunk, 0, 20);
  assert(NumNotSentRanges(chunk) == 1);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 0, 20));

  AckSomeDataSentFromChunk(chunk, 6, 17);
  assert(NumNotSentRanges(chunk) == 2);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 0, 6));
  assert(HasNotSentRange(chunk, 17, 20));

  AckSomeDataSentFromChunk(chunk, 0, 7);
  AckSomeDataSentFromChunk(chunk, 16, 22);
  assert(NumNotSentRanges(chunk) == 0);
  assert(NumUnackedRanges(chunk) == 0);

  AddNewRange(chunk, 0, 20);
  assert(NumNotSentRanges(chunk) == 1);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 0, 20));

  SomeDataSentFromChunk(chunk, 10);
  assert(NumNotSentRanges(chunk) == 1);
  assert(NumUnackedRanges(chunk) == 1);
  assert(HasNotSentRange(chunk, 10, 20));
  assert(HasUnackedRange(chunk, 0, 10));

  AckSomeDataSentFromChunk(chunk, 3, 7);
  assert(NumNotSentRanges(chunk) == 1);
  assert(NumUnackedRanges(chunk) == 2);
  assert(HasNotSentRange(chunk, 10, 20));
  assert(HasUnackedRange(chunk, 0, 3));
  assert(HasUnackedRange(chunk, 7, 10));

  SomeDataLostFromChunk(chunk, 0, 10);
  assert(NumNotSentRanges(chunk) == 2);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 7, 20));
  assert(HasNotSentRange(chunk, 0, 3));

  AckSomeDataSentFromChunk(chunk, 0, 20);
  assert(NumNotSentRanges(chunk) == 0);
  assert(NumUnackedRanges(chunk) == 0);

  AddNewRange(chunk, 3, 4);
  assert(NumNotSentRanges(chunk) == 1);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 3, 4));

  AddNewRange(chunk, 3, 4);
  assert(NumNotSentRanges(chunk) == 1);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 3, 4));

  AddNewRange(chunk, 2, 3);
  assert(NumNotSentRanges(chunk) == 1);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 2, 4));

  AddNewRange(chunk, 1, 3);
  assert(NumNotSentRanges(chunk) == 1);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 1, 4));

  AddNewRange(chunk, 2, 3);
  assert(NumNotSentRanges(chunk) == 1);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 1, 4));

  AddNewRange(chunk, 3, 4);
  assert(NumNotSentRanges(chunk) == 1);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 1, 4));

  AddNewRange(chunk, 1, 3);
  assert(NumNotSentRanges(chunk) == 1);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 1, 4));

  AddNewRange(chunk, 2, 5);
  assert(NumNotSentRanges(chunk) == 1);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 1, 5));

  AddNewRange(chunk, 5, 6);
  assert(NumNotSentRanges(chunk) == 1);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 1, 6));

  AddNewRange(chunk, 1, 7);
  assert(NumNotSentRanges(chunk) == 1);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 1, 7));

  AddNewRange(chunk, 0, 8);
  assert(NumNotSentRanges(chunk) == 1);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 0, 8));

  AddNewRange(chunk, 23, 24);
  assert(NumNotSentRanges(chunk) == 2);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 0, 8));
  assert(HasNotSentRange(chunk, 23, 24));

  AddNewRange(chunk, 23, 24);
  assert(NumNotSentRanges(chunk) == 2);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 0, 8));
  assert(HasNotSentRange(chunk, 23, 24));

  AddNewRange(chunk, 22, 23);
  assert(NumNotSentRanges(chunk) == 2);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 0, 8));
  assert(HasNotSentRange(chunk, 22, 24));

  AddNewRange(chunk, 21, 23);
  assert(NumNotSentRanges(chunk) == 2);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 0, 8));
  assert(HasNotSentRange(chunk, 21, 24));

  AddNewRange(chunk, 22, 23);
  assert(NumNotSentRanges(chunk) == 2);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 0, 8));
  assert(HasNotSentRange(chunk, 21, 24));

  AddNewRange(chunk, 23, 24);
  assert(NumNotSentRanges(chunk) == 2);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 0, 8));
  assert(HasNotSentRange(chunk, 21, 24));

  AddNewRange(chunk, 21, 23);
  assert(NumNotSentRanges(chunk) == 2);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 0, 8));
  assert(HasNotSentRange(chunk, 21, 24));

  AddNewRange(chunk, 22, 25);
  assert(NumNotSentRanges(chunk) == 2);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 0, 8));
  assert(HasNotSentRange(chunk, 21, 25));

  AddNewRange(chunk, 25, 26);
  assert(NumNotSentRanges(chunk) == 2);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 0, 8));
  assert(HasNotSentRange(chunk, 21, 26));

  AddNewRange(chunk, 21, 27);
  assert(NumNotSentRanges(chunk) == 2);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 0, 8));
  assert(HasNotSentRange(chunk, 21, 27));

  AddNewRange(chunk, 20, 28);
  assert(NumNotSentRanges(chunk) == 2);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 0, 8));
  assert(HasNotSentRange(chunk, 20, 28));

  AddNewRange(chunk, 13, 14);
  assert(NumNotSentRanges(chunk) == 3);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 0, 8));
  assert(HasNotSentRange(chunk, 13, 14));
  assert(HasNotSentRange(chunk, 20, 28));

  AddNewRange(chunk, 13, 14);
  assert(NumNotSentRanges(chunk) == 3);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 0, 8));
  assert(HasNotSentRange(chunk, 13, 14));
  assert(HasNotSentRange(chunk, 20, 28));

  AddNewRange(chunk, 12, 13);
  assert(NumNotSentRanges(chunk) == 3);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 0, 8));
  assert(HasNotSentRange(chunk, 12, 14));
  assert(HasNotSentRange(chunk, 20, 28));

  AddNewRange(chunk, 11, 13);
  assert(NumNotSentRanges(chunk) == 3);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 0, 8));
  assert(HasNotSentRange(chunk, 11, 14));
  assert(HasNotSentRange(chunk, 20, 28));

  AddNewRange(chunk, 12, 13);
  assert(NumNotSentRanges(chunk) == 3);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 0, 8));
  assert(HasNotSentRange(chunk, 11, 14));
  assert(HasNotSentRange(chunk, 20, 28));

  AddNewRange(chunk, 13, 14);
  assert(NumNotSentRanges(chunk) == 3);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 0, 8));
  assert(HasNotSentRange(chunk, 11, 14));
  assert(HasNotSentRange(chunk, 20, 28));

  AddNewRange(chunk, 11, 13);
  assert(NumNotSentRanges(chunk) == 3);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 0, 8));
  assert(HasNotSentRange(chunk, 11, 14));
  assert(HasNotSentRange(chunk, 20, 28));

  AddNewRange(chunk, 12, 15);
  assert(NumNotSentRanges(chunk) == 3);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 0, 8));
  assert(HasNotSentRange(chunk, 11, 15));
  assert(HasNotSentRange(chunk, 20, 28));

  AddNewRange(chunk, 15, 16);
  assert(NumNotSentRanges(chunk) == 3);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 0, 8));
  assert(HasNotSentRange(chunk, 11, 16));
  assert(HasNotSentRange(chunk, 20, 28));

  AddNewRange(chunk, 11, 17);
  assert(NumNotSentRanges(chunk) == 3);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 0, 8));
  assert(HasNotSentRange(chunk, 11, 17));
  assert(HasNotSentRange(chunk, 20, 28));

  AddNewRange(chunk, 10, 18);
  assert(NumNotSentRanges(chunk) == 3);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 0, 8));
  assert(HasNotSentRange(chunk, 10, 18));
  assert(HasNotSentRange(chunk, 20, 28));

  AddNewRange(chunk, 0, 28);
  assert(NumNotSentRanges(chunk) == 1);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 0, 28));

  AckSomeDataSentFromChunk(chunk, 0, 28);
  assert(NumNotSentRanges(chunk) == 0);
  assert(NumUnackedRanges(chunk) == 0);

  AddNewRange(chunk, 3, 4);
  AddNewRange(chunk, 10, 18);
  AddNewRange(chunk, 20, 28);
  assert(NumNotSentRanges(chunk) == 3);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 3, 4));
  assert(HasNotSentRange(chunk, 10, 18));
  assert(HasNotSentRange(chunk, 20, 28));

  AddNewRange(chunk, 2, 30);
  assert(NumNotSentRanges(chunk) == 1);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 2, 30));

  AckSomeDataSentFromChunk(chunk, 2, 30);
  assert(NumNotSentRanges(chunk) == 0);
  assert(NumUnackedRanges(chunk) == 0);

  AddNewRange(chunk, 3, 7);
  AddNewRange(chunk, 10, 18);
  AddNewRange(chunk, 20, 28);
  assert(NumNotSentRanges(chunk) == 3);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 3, 7));
  assert(HasNotSentRange(chunk, 10, 18));
  assert(HasNotSentRange(chunk, 20, 28));

  AddNewRange(chunk, 5, 25);
  assert(NumNotSentRanges(chunk) == 1);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 3, 28));

  AckSomeDataSentFromChunk(chunk, 3, 28);
  assert(NumNotSentRanges(chunk) == 0);
  assert(NumUnackedRanges(chunk) == 0);

  AddNewRange(chunk, 3, 5);
  AddNewRange(chunk, 10, 15);
  AddNewRange(chunk, 20, 25);
  AddNewRange(chunk, 30, 35);
  AddNewRange(chunk, 40, 45);
  assert(NumNotSentRanges(chunk) == 5);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 3, 5));
  assert(HasNotSentRange(chunk, 10, 15));
  assert(HasNotSentRange(chunk, 20, 25));
  assert(HasNotSentRange(chunk, 30, 35));
  assert(HasNotSentRange(chunk, 40, 45));

  AddNewRange(chunk, 10, 35);
  assert(NumNotSentRanges(chunk) == 3);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 3, 5));
  assert(HasNotSentRange(chunk, 10, 35));
  assert(HasNotSentRange(chunk, 40, 45));

  AckSomeDataSentFromChunk(chunk, 3, 45);
  assert(NumNotSentRanges(chunk) == 0);
  assert(NumUnackedRanges(chunk) == 0);

  AddNewRange(chunk, 3, 5);
  AddNewRange(chunk, 10, 15);
  AddNewRange(chunk, 20, 25);
  AddNewRange(chunk, 30, 35);
  AddNewRange(chunk, 40, 45);
  assert(NumNotSentRanges(chunk) == 5);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 3, 5));
  assert(HasNotSentRange(chunk, 10, 15));
  assert(HasNotSentRange(chunk, 20, 25));
  assert(HasNotSentRange(chunk, 30, 35));
  assert(HasNotSentRange(chunk, 40, 45));

  AddNewRange(chunk, 11, 33);
  assert(NumNotSentRanges(chunk) == 3);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 3, 5));
  assert(HasNotSentRange(chunk, 10, 35));
  assert(HasNotSentRange(chunk, 40, 45));

  AckSomeDataSentFromChunk(chunk, 3, 45);
  assert(NumNotSentRanges(chunk) == 0);
  assert(NumUnackedRanges(chunk) == 0);

  AddNewRange(chunk, 3, 5);
  AddNewRange(chunk, 10, 15);
  AddNewRange(chunk, 20, 25);
  AddNewRange(chunk, 30, 35);
  AddNewRange(chunk, 40, 45);
  assert(NumNotSentRanges(chunk) == 5);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 3, 5));
  assert(HasNotSentRange(chunk, 10, 15));
  assert(HasNotSentRange(chunk, 20, 25));
  assert(HasNotSentRange(chunk, 30, 35));
  assert(HasNotSentRange(chunk, 40, 45));

  AddNewRange(chunk, 10, 33);
  assert(NumNotSentRanges(chunk) == 3);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 3, 5));
  assert(HasNotSentRange(chunk, 10, 35));
  assert(HasNotSentRange(chunk, 40, 45));

  AckSomeDataSentFromChunk(chunk, 3, 45);
  assert(NumNotSentRanges(chunk) == 0);
  assert(NumUnackedRanges(chunk) == 0);

  AddNewRange(chunk, 3, 5);
  AddNewRange(chunk, 10, 15);
  AddNewRange(chunk, 20, 25);
  AddNewRange(chunk, 30, 35);
  AddNewRange(chunk, 40, 45);
  assert(NumNotSentRanges(chunk) == 5);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 3, 5));
  assert(HasNotSentRange(chunk, 10, 15));
  assert(HasNotSentRange(chunk, 20, 25));
  assert(HasNotSentRange(chunk, 30, 35));
  assert(HasNotSentRange(chunk, 40, 45));

  AddNewRange(chunk, 11, 35);
  assert(NumNotSentRanges(chunk) == 3);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 3, 5));
  assert(HasNotSentRange(chunk, 10, 35));
  assert(HasNotSentRange(chunk, 40, 45));

  AckSomeDataSentFromChunk(chunk, 3, 45);
  assert(NumNotSentRanges(chunk) == 0);
  assert(NumUnackedRanges(chunk) == 0);

  AddNewRange(chunk, 2, 9);
  AddNewRange(chunk, 10, 15);
  AddNewRange(chunk, 20, 25);
  AddNewRange(chunk, 30, 35);
  AddNewRange(chunk, 40, 45);
  assert(NumNotSentRanges(chunk) == 5);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 2, 9));
  assert(HasNotSentRange(chunk, 10, 15));
  assert(HasNotSentRange(chunk, 20, 25));
  assert(HasNotSentRange(chunk, 30, 35));
  assert(HasNotSentRange(chunk, 40, 45));

  AckSomeDataSentFromChunk(chunk, 0, 3);
  assert(NumNotSentRanges(chunk) == 5);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 3, 9));
  assert(HasNotSentRange(chunk, 10, 15));
  assert(HasNotSentRange(chunk, 20, 25));
  assert(HasNotSentRange(chunk, 30, 35));
  assert(HasNotSentRange(chunk, 40, 45));

  AckSomeDataSentFromChunk(chunk, 6, 7);
  assert(NumNotSentRanges(chunk) == 6);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 3, 6));
  assert(HasNotSentRange(chunk, 7, 9));
  assert(HasNotSentRange(chunk, 10, 15));
  assert(HasNotSentRange(chunk, 20, 25));
  assert(HasNotSentRange(chunk, 30, 35));
  assert(HasNotSentRange(chunk, 40, 45));

  AckSomeDataSentFromChunk(chunk, 0, 3);
  assert(NumNotSentRanges(chunk) == 6);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 3, 6));
  assert(HasNotSentRange(chunk, 7, 9));
  assert(HasNotSentRange(chunk, 10, 15));
  assert(HasNotSentRange(chunk, 20, 25));
  assert(HasNotSentRange(chunk, 30, 35));
  assert(HasNotSentRange(chunk, 40, 45));

  AckSomeDataSentFromChunk(chunk, 4, 8);
  assert(NumNotSentRanges(chunk) == 6);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 3, 4));
  assert(HasNotSentRange(chunk, 8, 9));
  assert(HasNotSentRange(chunk, 10, 15));
  assert(HasNotSentRange(chunk, 20, 25));
  assert(HasNotSentRange(chunk, 30, 35));
  assert(HasNotSentRange(chunk, 40, 45));

  AckSomeDataSentFromChunk(chunk, 3, 9);
  assert(NumNotSentRanges(chunk) == 4);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 10, 15));
  assert(HasNotSentRange(chunk, 20, 25));
  assert(HasNotSentRange(chunk, 30, 35));
  assert(HasNotSentRange(chunk, 40, 45));

  AckSomeDataSentFromChunk(chunk, 17, 20);
  assert(NumNotSentRanges(chunk) == 4);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 10, 15));
  assert(HasNotSentRange(chunk, 20, 25));
  assert(HasNotSentRange(chunk, 30, 35));
  assert(HasNotSentRange(chunk, 40, 45));

  AckSomeDataSentFromChunk(chunk, 17, 21);
  assert(NumNotSentRanges(chunk) == 4);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 10, 15));
  assert(HasNotSentRange(chunk, 21, 25));
  assert(HasNotSentRange(chunk, 30, 35));
  assert(HasNotSentRange(chunk, 40, 45));

  AckSomeDataSentFromChunk(chunk, 22, 41);
  assert(NumNotSentRanges(chunk) == 3);
  assert(NumUnackedRanges(chunk) == 0);
  assert(HasNotSentRange(chunk, 10, 15));
  assert(HasNotSentRange(chunk, 21, 22));
  assert(HasNotSentRange(chunk, 41, 45));

  FreeDataChunk(chunk);
}

#ifdef __cplusplus
}
#endif /* __cplusplus */
