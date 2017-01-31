#include "ps4.h"

#include <assert.h>

#define DEBUG_SOCKET
#include "defines.h"

#include "pup.h"
#include "pupup.h"

typedef struct _decrypt_state
{
  off_t input_base_offset;
  FILE* input_file;
  off_t output_base_offset;
  FILE* output_file;
  int device_fd;
  int pup_type;
}
decrypt_state;

int verify_segment(const decrypt_state state,
                   int index, pup_segment* segment, int additional)
{
  int result;
  uint8_t* buffer = NULL;

  buffer = memalign(0x4000, segment->compressed_size);
  fseek(state.input_file, state.input_base_offset + segment->offset, SEEK_SET);
  int read = fread(buffer, segment->compressed_size, 1, state.input_file);
  if (read != 1)
  {
    printfsocket("Failed to read segment #%d for verification! %d\n",
                 index, read);
    result = -1;
    goto end;
  }

  result = pupup_verify_segment(state.device_fd, index, buffer,
                                segment->compressed_size, additional);
  if (result != 0)
  {
    printfsocket("Failed to verify segment #%d! %d\n", index, errno);
    goto end;
  }

end:
  if (buffer != NULL)
  {
    free(buffer);
  }

  return result;
}

int verify_segments(const decrypt_state state,
                    pup_segment* segments, int segment_count)
{
  int result = 0;

  for (int i = 0; i < segment_count; i++)
  {
    pup_segment* segment = &segments[i];
    if ((segment->flags & 0xF0000000) == 0xE0000000)
    {
      printfsocket("Verifying segment #%d (%d)... [1]\n",
                   i, segment->flags >> 20);
      result = verify_segment(state, i, segment, 1);
      if (result < 0)
      {
        goto end;
      }
    }
  }

  for (int i = 0; i < segment_count; i++)
  {
    pup_segment* segment = &segments[i];
    if ((segment->flags & 0xF0000000) == 0xF0000000)
    {
      printfsocket("Verifying segment #%d (%d)... [0]\n",
                   i, segment->flags >> 20);
      result = verify_segment(state, i, segment, 0);
      if (result < 0)
      {
        goto end;
      }
    }
  }

end:
  return result;
}

int decrypt_segment(const decrypt_state state,
                    uint16_t index, pup_segment* segment)
{
  int result = -1;
  uint8_t* buffer = NULL;

  buffer = memalign(0x4000, segment->compressed_size);
  fseek(state.input_file,
        state.input_base_offset + segment->offset, SEEK_SET);
  fseek(state.output_file,
        state.output_base_offset + segment->offset, SEEK_SET);

  int is_compressed = (segment->flags & 8) != 0 ? 1 : 0;

  size_t remaining_size = segment->compressed_size;
  if (is_compressed == 1)
  {
    remaining_size &= ~0xFull;
  }

  if (remaining_size > 0)
  {
    size_t padding_size = segment->compressed_size & 0xF;
    size_t encrypted_size = remaining_size;

    if (segment->compressed_size < remaining_size)
    {
      encrypted_size = segment->compressed_size;
    }

    int read = fread(buffer, encrypted_size, 1, state.input_file);
    if (read != 1)
    {
      printfsocket("Failed to read segment #%d! #%d\n", index, read);
      result = -1;
      goto end;
    }

    result = pupup_decrypt_segment(state.device_fd,
                                   index, buffer, encrypted_size);
    if (result != 0)
    {
      printfsocket("Failed to decrypt segment #%d! %d\n", index, errno);
      goto end;
    }

    int unencrypted_size = remaining_size - padding_size;
    if (is_compressed == 0 || encrypted_size != remaining_size)
    {
      unencrypted_size = encrypted_size;
    }

    fwrite(buffer, unencrypted_size, 1, state.output_file);
  }

end:
  if (buffer != NULL)
  {
    free(buffer);
  }

  return result;
}

int decrypt_segment_blocks(const decrypt_state state,
                           uint16_t index, pup_segment* segment,
                           uint16_t table_index, pup_segment* table_segment)
{
  int result = -1;
  uint8_t* table_buffer = NULL;
  uint8_t* block_buffer = NULL;

  size_t table_length = table_segment->compressed_size;
  table_buffer = memalign(0x4000, table_length);
  fseek(state.input_file,
        state.input_base_offset + table_segment->offset, SEEK_SET);

  int read = fread(table_buffer, table_length, 1, state.input_file);
  if (read != 1)
  {
    printfsocket("  Failed to read table for segment #%d! %d\n", index, read);
    result = -1;
    goto end;
  }

  printfsocket("  Decrypting table #%d for segment #%d\n", table_index, index);
  result = pupup_decrypt_segment(state.device_fd,
                                 table_index, table_buffer, table_length);
  if (result != 0)
  {
    printfsocket("  Failed to decrypt table for segment #%d! %d\n",
                 index, errno);
    goto end;
  }

  int is_compressed = (segment->flags & 8) != 0 ? 1 : 0;

  size_t block_size = 1 << (((segment->flags & 0xF000) >> 12) + 12);
  size_t block_count = (block_size + segment->uncompressed_size - 1)
                       / block_size;

  size_t tail_size = segment->uncompressed_size % block_size;
  if (tail_size == 0)
  {
    tail_size = block_size;
  }

  pup_block_info* block_infos = NULL;
  if (is_compressed == 1)
  {
    size_t valid_table_length = block_count * (32 + sizeof(pup_block_info));
    if (valid_table_length != table_length)
    {
      printfsocket("  Strange segment #%d table: %llu vs %llu\n",
                   index, valid_table_length, table_length);
    }
    block_infos = (pup_block_info*)&table_buffer[32 * block_count];
  }

  block_buffer = memalign(0x4000, block_size);

  fseek(state.input_file,
        state.input_base_offset + segment->offset, SEEK_SET);
  fseek(state.output_file,
        state.output_base_offset + segment->offset, SEEK_SET);

  printfsocket("  Decrypting %d blocks...\n", block_count);

  size_t remaining_size = segment->compressed_size;
  int last_index = block_count - 1;
  for (int i = 0; i < block_count; i++)
  {
    //printfsocket("  Decrypting block %d/%d...\n", i, block_count);

    size_t read_size;

    if (is_compressed == 1)
    {
      pup_block_info* block_info = &block_infos[i];
      uint32_t unpadded_size = (block_info->size & ~0xFu) -
                               (block_info->size & 0xFu);

      read_size = block_size;
      if (unpadded_size != block_size)
      {
        read_size = block_info->size;
        if (i != last_index || tail_size != block_info->size)
        {
          read_size &= ~0xFu;
        }
      }

      if (block_info->offset != 0)
      {
        off_t block_offset = segment->offset + block_info->offset;
        fseek(state.input_file,
              state.input_base_offset + block_offset, SEEK_SET);
        fseek(state.output_file,
              state.output_base_offset + block_offset, SEEK_SET);
      }
    }
    else
    {
      read_size = remaining_size;
      if (block_size < read_size)
      {
        read_size = block_size;
      }
    }

    read = fread(block_buffer, read_size, 1, state.input_file);
    if (read != 1)
    {
      printfsocket("  Failed to read block %d for segment #%d! %d\n",
                   i, index, read);
      goto end;
    }

    result = pupup_decrypt_segment_block(state.device_fd,
                                        index, i, block_buffer, read_size,
                                        table_buffer, table_length);
    if (result < 0)
    {
      printfsocket("  Failed to decrypt block for segment #%d! %d\n",
                   index, errno);
      goto end;
    }

    fwrite(block_buffer, read_size, 1, state.output_file);

    remaining_size -= read_size;
  }

end:
  if (block_buffer != NULL)
  {
    free(block_buffer);
  }

  if (table_buffer != NULL)
  {
    free(table_buffer);
  }

  return result;
}

int find_table_segment(int index, pup_segment* segments, int segment_count,
                       int* table_index)
{
  if (((index | 0x100) & 0xF00) == 0xF00)
  {
    printfsocket("Can't do table for segment #%d\n", index);
    *table_index = -1;
    return -1;
  }

  for (int i = 0; i < segment_count; i++)
  {
    if (segments[i].flags & 1)
    {
      uint32_t id = segments[i].flags >> 20;
      if (id == index)
      {
        *table_index = i;
        return 0;
      }
    }
  }

  return -2;
}

int decrypt_pup_data(const decrypt_state state)
{
  int result;
  size_t read;
  uint8_t* header_data = NULL;

  fseek(state.input_file, state.input_base_offset, SEEK_SET);

  pup_file_header file_header;
  read = fread(&file_header, sizeof(file_header), 1, state.input_file);
  if (read != 1)
  {
    printfsocket("Failed to read file header! (%u)\n", read);
    goto end;
  }

  int header_size = file_header.unknown_0C + file_header.unknown_0E;

  header_data = memalign(0x4000, header_size);
  memcpy(header_data, &file_header, sizeof(file_header));

  read = fread(&header_data[sizeof(file_header)],
               header_size - sizeof(file_header), 1, state.input_file);
  if (read != 1)
  {
    printfsocket("Failed to read header! (%u)\n", read);
    goto end;
  }

  if ((file_header.flags & 1) == 0)
  {
    printfsocket("Decrypting header...\n");
    result = pupup_decrypt_header(state.device_fd,
                                  header_data, header_size,
                                  0);//state.pup_type);
    if (result != 0)
    {
      printfsocket("Failed to decrypt header! %d\n", errno);
      goto end;
    }
  }
  else
  {
    printfsocket("Can't decrypt network pup!\n");
    goto end;
  }

  pup_header* header = (pup_header*)&header_data[0];
  pup_segment* segments = (pup_segment*)&header_data[0x20];

  fseek(state.output_file, state.output_base_offset, SEEK_SET);
  fwrite(header_data, header_size, 1, state.output_file);

  printfsocket("Verifying segments...\n");
  result = verify_segments(state, segments, header->segment_count);
  if (result < 0)
  {
    printfsocket("Failed to verify segments!\n");
  }

  /*
  for (int i = 0; i < header->segment_count; i++)
  {
    pup_segment* segment = &segments[i];
    printfsocket("%4d i=%4u b=%u c=%u t=%u r=%05X\n",
                  i, segment->flags >> 20,
                  (segment->flags & 0x800) != 0,
                  (segment->flags & 0x8) != 0,
                  (segment->flags & 0x1) != 0,
                   segment->flags & 0xFF7F6);
  }
  */

  printfsocket("Decrypting %d segments...\n", header->segment_count);
  for (int i = 0; i < header->segment_count; i++)
  {
    pup_segment* segment = &segments[i];

    uint32_t special = segment->flags & 0xF0000000;
    if (special == 0xE0000000)
    {
      printfsocket("Skipping additional signature segment #%d!\n", i);
      continue;
    }
    else if (special == 0xF0000000)
    {
      printfsocket("Skipping watermark segment #%d!\n", i);
      continue;
    }

    printfsocket("Decrypting segment %d/%d...\n",
                 1 + i, header->segment_count);

    if ((segment->flags & 0x800) != 0)
    {
      int table_index;
      result = find_table_segment(i, segments, header->segment_count,
                                  &table_index);
      if (result < 0)
      {
        printfsocket("Failed to find table for segment #%d!\n", i);
        continue;
      }

      decrypt_segment_blocks(state, i, segment,
                             table_index, &segments[table_index]);
    }
    else
    {
      decrypt_segment(state, i, segment);
    }
  }

end:
  if (header_data != NULL)
  {
    free(header_data);
  }

  return 0;
}

int get_pup_type(const char* name)
{
  if (strcmp(name, "PS4UPDATE1.PUP") == 0 ||
      strcmp(name, "PS4UPDATE2.PUP") == 0)
  {
    return 1;
  }

  if (strcmp(name, "PS4UPDATE3.PUP") == 0 ||
      strcmp(name, "PS4UPDATE4.PUP") == 0)
  {
    return 0;
  }

  return -1;
}

void decrypt_pup(const char* name, FILE* input, off_t baseOffset, int fd)
{
  FILE* output = NULL;

  char path[260];
  sprintf(path, "/mnt/usb0/%s.dec", name);

  printfsocket("Creating %s...\n", path);

  output = fopen(path, "wb");
  if (output == NULL)
  {
    printfsocket("Failed to open %s!\n", path);
    goto end;
  }

  int type = get_pup_type(name);
  if (type < 0)
  {
    printfsocket("Don't know the type for %s!\n", path);
    goto end;
  }

  decrypt_state state;
  state.input_file = input;
  state.input_base_offset = baseOffset;
  state.output_file = output;
  state.output_base_offset = 0;
  state.device_fd = fd;
  state.pup_type = type;
  decrypt_pup_data(state);

end:
  if (output != NULL)
  {
    fclose(output);
  }
}

typedef struct _bls_entry
{
  uint32_t block_offset;
  uint32_t size;
  uint8_t reserved[8];
  char name[32];
}
bls_entry;
CHECK_SIZE(bls_entry, 48);

typedef struct _bls_header
{
  uint32_t magic;
  uint32_t version;
  uint32_t flags;
  uint32_t file_count;
  uint32_t block_count;
  uint8_t reserved[12];
}
bls_header;
CHECK_SIZE(bls_header, 32);

void decrypt_pups()
{
  const char* path = "/mnt/usb0/PS4UPDATE.PUP";

  int read;
  int fd = -1;
  FILE* input = NULL;
  bls_entry* entries = NULL;

  fd = open("/dev/pup_update0", O_RDWR, 0);
  if (fd < 0)
  {
    printfsocket("Failed to open /dev/pup_update0!\n");
    goto end;
  }

  printfsocket("Opening %s...\n", path);
  input = fopen(path, "rb");
  if (input == NULL)
  {
    printfsocket("Failed to open %s!\n", path);
    goto end;
  }

  bls_header header;
  read = fread(&header, sizeof(header), 1, input);
  if (read != 1)
  {
    printfsocket("Failed to read BLS header!\n");
    goto end;
  }

  entries = (bls_entry*)malloc(sizeof(bls_entry) * header.file_count);
  read = fread(entries, sizeof(bls_entry), header.file_count, input);
  if (read != header.file_count)
  {
    printfsocket("Failed to read BLS entries!\n");
    goto end;
  }

  for (int i = 0; i < header.file_count; i++)
  {
    decrypt_pup(entries[i].name, input, entries[i].block_offset * 512, fd);
  }

end:
  if (entries != NULL)
  {
    free(entries);
  }

  if (input != NULL)
  {
    fclose(input);
  }

  if (fd >= 0)
  {
    close(fd);
  }
}
