#ifndef __UBI_H__
#define __UBI_H__
#include <stdint.h>
#include <stddef.h>

#define UBI_SKIP_BOOTLOADER  1*1024*1024
#define UBI_MAX_VOLUME       128
#define UBI_MIN_BLOCK        8192
#define UBI_VOLUME_MAX_BLOCK 8192 
#define UBI_VOL_NAME_MAX     127

typedef struct {
    int (*block_read)(uint64_t addr, uint8_t *data, uint32_t size);
    int (*block_write)(uint64_t addr, uint8_t *data, uint32_t size);
    int (*block_erase)(uint64_t address, uint32_t size);
}ubi_io_t;


typedef struct{
   uint32_t id;
   char    name[UBI_VOL_NAME_MAX + 1];
   uint32_t reserved_pebs;
   uint8_t vol_type;
   uint32_t blk_count;
   uint32_t blk_map[UBI_VOLUME_MAX_BLOCK]; 
}ubi_volume_t;

typedef struct{
    int volume_cnt;
    ubi_volume_t *volume[UBI_MAX_VOLUME];
    uint32_t free_blk_map[UBI_VOLUME_MAX_BLOCK];
    uint32_t free_blk_cnt;
    uint32_t major_layout;
    uint32_t minor_layout;
}ubi_info_t;

typedef struct {
    uint32_t page_size;
    uint32_t page_per_block;
    uint32_t block_per_die;
    uint32_t spare_size;
    uint32_t ndies;
    uint64_t total_size;
}flash_info_t;

typedef struct {
    ubi_io_t* io;
    ubi_info_t* info;
    flash_info_t *flash;
    int ubi_offset;
    int peb_size;
    int leb_size;
    uint8_t *rcache;
    uint8_t *wcache;
}ubi_t;

ubi_t* UbiInit(ubi_io_t *io, flash_info_t *flash);
void UbiDeinit(ubi_t *);
//int UbiCreateVolume(ubi_t* ubi, char* name,  int lebs, int type);
//int UbiDeleteVolume(ubi_t* ubi, char* name);
uint64_t UbiVolumeGetSize(ubi_t *ubi, char* volume);
int UbiVolumeErase(ubi_t* ubi,const  char* volume);
int UbiVolumeWrite(ubi_t* ubi,const  char* volume, uint8_t* data, size_t len);
int UbiVolumeRead(ubi_t* ubi, const char* volume, uint8_t* data, size_t len);
int UbiVolumeCreate(ubi_t *ubi,  const char* name, int type, uint64_t size);
#endif
