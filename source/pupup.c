#include <assert.h>

#include "ps4.h"

#define DEBUG_SOCKET
#include "defines.h"

#include "pupup.h"

typedef struct _decrypt_header_args
{
  void* buffer;
  size_t length;
  int type;
}
decrypt_header_args;
CHECK_SIZE(decrypt_header_args, 24);

int translate_type(int type)
{
  switch (type)
  {
    case 0:
    case 3: return 0;
    case 1:
    case 4: return 1;
    case 2:
    case 5: return 2;
  }
  return 0;
}

int pupup_decrypt_header(int fd, void* buffer, size_t length, int type)
{
  decrypt_header_args args;
  memset(&args, 0, sizeof(args));
  args.buffer = buffer,
  args.length = length;
  args.type = translate_type(type);
  return ioctl(fd, 0xC0184401, &args);
}

typedef struct _verify_segment_args
{
  uint16_t index;
  void* buffer;
  size_t length;
}
verify_segment_args;
CHECK_SIZE(verify_segment_args, 24);

int pupup_verify_segment(int fd, uint16_t index, void* buffer, size_t length,
                         int additional)
{
  verify_segment_args args;
  memset(&args, 0, sizeof(args));
  args.index = index;
  args.buffer = buffer,
  args.length = length;
  int op = additional != 0 ? 0xC0184402 : 0xC0184403;
  return ioctl(fd, op, &args);
}

typedef struct _decrypt_segment_args
{
  uint16_t index;
  void* buffer;
  size_t length;
}
decrypt_segment_args;
CHECK_SIZE(decrypt_segment_args, 24);

int pupup_decrypt_segment(int fd, uint16_t index, void* buffer, size_t length)
{
  decrypt_segment_args args;
  memset(&args, 0, sizeof(args));
  args.index = index;
  args.buffer = buffer,
  args.length = length;
  return ioctl(fd, 0xC0184404, &args);
}

typedef struct _decrypt_segment_block_args
{
  uint16_t entry_index;
  uint16_t block_index;
  void* block_buffer;
  size_t block_length;
  void* table_buffer;
  size_t table_length;
}
decrypt_segment_block_args;
CHECK_SIZE(decrypt_segment_block_args, 40);

int pupup_decrypt_segment_block(int fd,
                                uint16_t entry_index,
                                uint16_t block_index, void* block_buffer,
                                size_t block_length,
                                void* table_buffer, size_t table_length)
{
  decrypt_segment_block_args args;
  memset(&args, 0, sizeof(args));
  args.entry_index = entry_index;
  args.block_index = block_index;
  args.block_buffer = block_buffer,
  args.block_length = block_length;
  args.table_buffer = table_buffer;
  args.table_length = table_length;
  return ioctl(fd, 0xC0284405, &args);
}
