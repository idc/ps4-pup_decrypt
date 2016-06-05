#ifndef __PUP_UPDATE
#define __PUP_UPDATE

int pupup_decrypt_header(int fd, void* buffer, size_t length, int type);
int pupup_verify_segment(int fd, uint16_t index, void* buffer, size_t length,
                         int additional);
int pupup_decrypt_segment(int fd, uint16_t index, void* buffer, size_t length);
int pupup_decrypt_segment_block(int fd,
                                uint16_t entry_index,
                                uint16_t block_index, void* block_buffer,
                                size_t block_length,
                                void* table_buffer, size_t table_length);

#endif
