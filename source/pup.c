#include <assert.h>

#include "ps4.h"

#define DEBUG_SOCKET
#include "defines.h"

#include "pup.h"

const uint8_t pup_signature[] = { 0x4F, 0x15, 0x3D, 0x1D };

CHECK_SIZE(pup_file_header, 16);
CHECK_SIZE(pup_header, 32);
CHECK_SIZE(pup_segment, 32);
CHECK_SIZE(pup_block_info, 8);
