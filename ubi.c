#include <fel.h>
#include <ubi.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define B16  __builtin_bswap16
#define B32  __builtin_bswap32
#define B64  __builtin_bswap64

typedef struct  __attribute__((packed)){
    uint32_t magic;
    uint8_t version;
    uint8_t padding1[3];
    uint64_t ec;
    uint32_t vid_hdr_offset;
    uint32_t data_offset;
    uint32_t image_seq;
    uint8_t padding2[32];
    uint32_t hdr_crc;
} ubi_ec_hdr;

typedef struct  __attribute__((packed)){
    uint32_t magic;
    uint8_t version;
    uint8_t vol_type;
    uint8_t copy_flag;
    uint8_t compat;
    uint32_t vol_id;
    uint32_t lnum;
    uint8_t padding1[4];
    uint32_t data_size;
    uint32_t used_ebs;
    uint32_t data_pad;
    uint32_t data_crc;
    uint8_t padding2[4];
    uint64_t  sqnum;
    uint8_t padding3[12];
    uint32_t hdr_crc;
} ubi_vid_hdr ;


typedef struct  __attribute__ ((packed)){
    uint32_t reserved_pebs;
    uint32_t alignment;
    uint32_t data_pad;
    uint8_t vol_type;
    uint8_t padding1;
    uint16_t name_len;
    uint8_t name[UBI_VOL_NAME_MAX + 1];
    uint8_t padding2[24];
    uint32_t crc;
} ubi_vol_tbl_record ;

uint32_t uiReflect(uint32_t uiData, uint8_t ucLength)
{
    uint32_t uiMask = 1 << (ucLength - 1), uiMaskRef = 1, uiDataReturn = 0;

    for(; uiMask; uiMask >>= 1)
    {
        if(uiData & uiMask)
            uiDataReturn |= uiMaskRef;

        uiMaskRef <<= 1;
    }

    return uiDataReturn;
}


uint32_t JAMCRC(const void *pucDataBuff, uint32_t uiLength)
{
    uint32_t uiPolynomial = 0x04C11DB7, uiInputCRC = 0xFFFFFFFF, i = 0;
    uint8_t ucMask = 0;

    uiPolynomial = uiReflect(uiPolynomial, 32);

    for(i = 0; i < uiLength; ++i)
    {
        uiInputCRC ^= *(uint8_t *)pucDataBuff++;

        for(ucMask = 1; ucMask; ucMask <<= 1)
        {
            if(uiInputCRC & 1)
                uiInputCRC = (uiInputCRC >> 1) ^ uiPolynomial;
            else
                uiInputCRC >>= 1;
        }
    }

    return uiInputCRC;
}

int ubi_read_block(ubi_t *ubi, uint64_t addr, void *data, uint32_t len){
    ubi->io->block_read(ubi->ubi_offset + addr, (uint8_t*)data, len);
    return 0;
}

int ubi_erase_block(ubi_t *ubi, uint64_t addr){
    ubi->io->block_erase(ubi->ubi_offset + addr, ubi->peb_size);
    return 0;
}

int ubi_write_block(ubi_t *ubi, uint64_t addr, void *data, uint32_t len){
    ubi->io->block_write(ubi->ubi_offset + addr, (uint8_t*)data, len);
    return 0;
}

void ubi_free_blk_put(ubi_t* ubi, int pnum){
    ubi->info->free_blk_map[ubi->info->free_blk_cnt] = pnum;
    ubi->info->free_blk_cnt++;
}

int ubi_free_blk_get(ubi_t* ubi){
    ubi->info->free_blk_cnt--;
    return ubi->info->free_blk_map[ubi->info->free_blk_cnt];
}

int ubi_get_ec_hdr(ubi_t* ubi, ubi_ec_hdr *hdr, int pnum){
    ubi_read_block(ubi, pnum * ubi->peb_size,  hdr, sizeof(ubi_ec_hdr));     
    if(memcmp(&hdr->magic, "UBI#", 4) != 0 || (JAMCRC(hdr, sizeof(ubi_ec_hdr) - 4) != B32(hdr->hdr_crc))){
        return 0;
    }  
    if(B64(hdr->ec) > 0x7FFFFFFF)
        return 0;

    return 1;
}

int ubi_get_vid_hdr(ubi_t* ubi, ubi_vid_hdr *hdr, int pnum, uint32_t offset){
    ubi_read_block(ubi, pnum * ubi->peb_size + offset,  hdr, sizeof(ubi_vid_hdr));     
    if(memcmp(&hdr->magic, "UBI!", 4) != 0 || (JAMCRC(hdr, sizeof(ubi_vid_hdr) - 4) != B32(hdr->hdr_crc))){
        return 0;
    }  
    return 1;
}

void ubi_search(ubi_t *ubi){
    uint64_t offset = UBI_SKIP_BOOTLOADER;
    uint64_t first_block = -1;
    uint8_t buf[16];
    for(int i = 0; i < ubi->flash->block_per_die * ubi->flash->ndies; i++){
        ubi->io->block_read(offset, buf, 4);
        //printf("read %llu %08x\n", offset, *(uint32_t*)buf);
        if(memcmp((const char*)buf, "UBI#", 4) == 0){
            if(first_block > offset)
                first_block = offset;
            else{
                printf("UBI Scaning...\n");
                ubi->ubi_offset = first_block;
                ubi->peb_size = offset - first_block;
                ubi->leb_size = ubi->peb_size - (2 * ubi->flash->page_size);
                return;
            }
        }
        offset += ubi->flash->page_size * ubi->flash->page_per_block; 
    }
}

void ubi_layout(ubi_t *ubi){
    int pnum = ubi->info->major_layout;
    ubi_ec_hdr ec;
    if(!ubi_get_ec_hdr(ubi,  &ec, pnum)){
        printf("bad ubi layout volume!\n");
        return;
    }
    
    int size = ubi->leb_size;
    uint8_t *tbl = malloc(size);

    if(tbl){
        ubi_read_block(ubi, pnum * ubi->peb_size + B32(ec.data_offset),  tbl, size); 
        printf("UBI partition table:\n");
        for(int i = 0 ; i < UBI_MAX_VOLUME; i++){
            ubi_vol_tbl_record *vrec = (ubi_vol_tbl_record*)(tbl + sizeof(ubi_vol_tbl_record) * i);
            if(B32(vrec->reserved_pebs) <= 0 || JAMCRC(vrec, sizeof(ubi_vol_tbl_record) - 4) != B32(vrec->crc)){
                continue;
            }

            if(ubi->info->volume[i] == 0){ 
                ubi->info->volume[i] = calloc(1, sizeof(ubi_volume_t));
                ubi->info->volume_cnt++;
            }
            strncpy(ubi->info->volume[i]->name, (char*)vrec->name, UBI_VOL_NAME_MAX);
            ubi->info->volume[i]->reserved_pebs = B32(vrec->reserved_pebs);
            ubi->info->volume[i]->vol_type = vrec->vol_type;
            printf("%-16s:   %-8u KB\n",  vrec->name, B32(vrec->reserved_pebs)*ubi->leb_size/1024);
        }
        printf("\n");
        free(tbl);
    }
}

void ubi_scan(ubi_t *ubi){
	struct progress_t p;

    ubi->info = calloc(1, sizeof(ubi_info_t));
    uint32_t  blocks = (ubi->flash->total_size - ubi->ubi_offset) / ubi->peb_size;
	progress_start(&p, blocks*ubi->peb_size);
    for(int pnum = 0; pnum < blocks; pnum++){
        //parse erase count header
        ubi_ec_hdr ec;
        if(ubi_get_ec_hdr(ubi, &ec, pnum)) {
            //prase volume id header
            ubi_vid_hdr vid;
            if(ubi_get_vid_hdr(ubi, &vid, pnum, B32(ec.vid_hdr_offset))){
                int vol_id = B32(vid.vol_id);  
                int lnum = B32(vid.lnum);
                if(vol_id == 0x7fffefff){
                    ubi->info->minor_layout = ubi->info->major_layout;
                    ubi->info->major_layout = pnum;
                }else{
                    if(ubi->info->volume[vol_id] == 0){
                        ubi->info->volume_cnt ++;
                        ubi->info->volume[vol_id] = calloc(1, sizeof(ubi_volume_t));
                        //printf("found new volume: %d\n",  vol_id);
                    }
                    //printf("map %d to volume %d : %d d\n", pnum, vol_id, lnum);
                    ubi->info->volume[vol_id]->blk_count++;
                    ubi->info->volume[vol_id]->blk_map[lnum] = pnum;
                }
            }else if(*(uint64_t*)&vid == 0xFFFFFFFFFFFFFFFF){
                ubi_free_blk_put(ubi, pnum);
            }else{
                printf("bad vid %d %08x %08x %08x\n", pnum, *(uint32_t*)&vid, B32(vid.hdr_crc), JAMCRC(&vid, sizeof(vid) - 4));
                ec.ec = B64(B64(ec.ec) + 1);
                ec.data_offset = B32(ubi->flash->page_size * 2);
                ec.vid_hdr_offset = B32(ubi->flash->page_size);
                ec.hdr_crc = B32(JAMCRC(&ec, sizeof(ec) - 4));
                ubi_erase_block(ubi, pnum * ubi->peb_size);
                ubi_write_block(ubi, pnum * ubi->peb_size, &ec, sizeof(ec));
                ubi_free_blk_put(ubi, pnum);
                continue; 
            }
        }else{
            printf("bad ec %d\n", pnum);
            memcpy(&ec.magic, "UBI#", 4);
            ec.data_offset = B32(ubi->flash->page_size * 2);
            ec.vid_hdr_offset = B32(ubi->flash->page_size);
            ec.version = 1;
            ec.ec = B64(1);
            ec.hdr_crc = B32(JAMCRC(&ec, sizeof(ec) - 4));
            ubi_erase_block(ubi, pnum * ubi->peb_size);
            ubi_write_block(ubi, pnum * ubi->peb_size, &ec, sizeof(ec));
            ubi_free_blk_put(ubi, pnum);
        }
        progress_update(&p, ubi->peb_size);
    }
    progress_stop(&p);
    ubi_layout(ubi);
}

int ubi_find_volume(ubi_t *ubi, const char* name){
    for(int i = 0; i < ubi->info->volume_cnt; i++){
        if(strcmp((const char*)ubi->info->volume[i]->name, name) == 0){
            return i;
        }
    }
    return -1;
}

ubi_volume_t* ubi_get_volume(ubi_t *ubi, const char* name){
    for(int i = 0; i < ubi->info->volume_cnt; i++){
        if(strcmp((const char*)ubi->info->volume[i]->name, name) == 0){
            return ubi->info->volume[i];
        }
    }
    return NULL;
}


ubi_t* UbiInit(ubi_io_t *io, flash_info_t *flash){
    ubi_t* ubi = malloc(sizeof(ubi_t));
    ubi->flash = flash;
    flash->total_size = flash->block_per_die * flash->ndies * flash->page_per_block * flash->page_size;
    ubi->io = io;

    ubi_search(ubi);
    ubi->rcache = malloc(ubi->peb_size);
    ubi->wcache = malloc(ubi->peb_size);

    ubi_scan(ubi);
    return ubi;
}

void UbiDeinit(ubi_t *ubi){
    free(ubi->rcache);
    free(ubi->wcache);
    free(ubi);
}


int UbiVolumeErase(ubi_t* ubi, const char* name){
	struct progress_t p;
    int id = ubi_find_volume(ubi, name);
    ubi_volume_t *volume = ubi->info->volume[id];
    if(id >= 0){
        progress_start(&p, volume->blk_count*ubi->peb_size);
        for(int i = volume->blk_count - 1; i >= 0; i--){
            ubi_ec_hdr ec = {0};
            int pnum = volume->blk_map[i];
            ubi_read_block(ubi, pnum * ubi->peb_size,  &ec, sizeof(ubi_ec_hdr));      
            if(memcmp(&ec.magic, "UBI#", 4) != 0){
                memcpy(&ec.magic, "UBI#", 4);
                ec.data_offset = B32(ubi->flash->page_size * 2);
                ec.vid_hdr_offset = B32(ubi->flash->page_size);
                ec.version = 1;
            }
            ec.ec += B64(B64(ec.ec) + 1);
            ec.hdr_crc = B32(JAMCRC(&ec, sizeof(ec) - 4));
            ubi_erase_block(ubi, pnum * ubi->peb_size);
            ubi_write_block(ubi, pnum * ubi->peb_size, &ec, sizeof(ec));
            ubi_free_blk_put(ubi, pnum);
            volume->blk_count--;
            progress_update(&p, ubi->peb_size);
        }
        progress_stop(&p);
        return 0;
    }
    return -1;
}

int UbiVolumeWrite(ubi_t* ubi, const char* name, uint8_t* data, size_t len){
    struct progress_t p;
    int id = ubi_find_volume(ubi, name);
    if(id >= 0){
        ubi_volume_t *volume = ubi->info->volume[id];
        for(int i = volume->blk_count - 1; i >= 0; i--){
            ubi_ec_hdr ec = {0};
            int pnum = volume->blk_map[i];
            ubi_read_block(ubi, pnum * ubi->peb_size,  &ec, sizeof(ubi_ec_hdr));      
            if(memcmp(&ec.magic, "UBI#", 4) != 0 || (JAMCRC(&ec, sizeof(ec) - 4) != B32(ec.hdr_crc))){
                memcpy(&ec.magic, "UBI#", 4);
                ec.data_offset = ubi->flash->page_size * 2;
                ec.vid_hdr_offset = ubi->flash->page_size;
                ec.version = 1;
            }
            ec.ec = B64((B64(ec.ec)) + 1);
            ec.hdr_crc = B32(JAMCRC(&ec, sizeof(ec) - 4));
            ubi_erase_block(ubi, pnum * ubi->peb_size);
            ubi_write_block(ubi, pnum * ubi->peb_size, &ec, sizeof(ec));
            ubi_free_blk_put(ubi, pnum);
        }
        volume->blk_count = 0;

        progress_start(&p, len);
        for(int i = 0; i < volume->reserved_pebs; i++){
            int pnum = ubi_free_blk_get(ubi);
            ubi_ec_hdr ec;
            ubi_read_block(ubi, pnum * ubi->peb_size,  &ec, sizeof(ubi_ec_hdr));   

            ubi_vid_hdr vid = {0};
            memcpy(&vid.magic,"UBI!", 4);
            vid.version = 1;
            vid.vol_type  = 1;
            vid.copy_flag = 0;
            vid.compat = 0;
            vid.vol_id = B32(id);
            vid.lnum = B32(i);
            vid.data_size = 0;
            vid.sqnum = 0;
            vid.hdr_crc = B32(JAMCRC(&vid, sizeof(vid) - 4));

            int write_size = ubi->leb_size;
            if(len < write_size)
                write_size = len;
            ubi_write_block(ubi, pnum * ubi->peb_size + B32(ec.data_offset), data, write_size);
            ubi_write_block(ubi, pnum * ubi->peb_size + B32(ec.vid_hdr_offset),  &vid, sizeof(ubi_vid_hdr));      
            len -= write_size;
            data += write_size;
            progress_update(&p, write_size);
            volume->blk_map[volume->blk_count] = pnum;
            volume->blk_count++;
            if(len <= 0)
                break;
        }
        progress_stop(&p);
        return 0;
    }

    return -1;
}

int UbiVolumeRead(ubi_t* ubi, const char* name, uint8_t* data, size_t len){
    struct progress_t p;
    int id = ubi_find_volume(ubi, name);
    if(id >= 0){
    
        ubi_volume_t *volume = ubi->info->volume[id];
        progress_start(&p, volume->blk_count*ubi->leb_size);
        for(int i = 0; i < volume->blk_count; i++){
            int pnum = volume->blk_map[i];
            ubi_ec_hdr ec;
            ubi_read_block(ubi, pnum * ubi->peb_size,  &ec, sizeof(ubi_ec_hdr));      
            int read_size = ubi->leb_size;
            if(len < read_size)
                read_size = len;
            ubi_read_block(ubi, pnum * ubi->peb_size + B32(ec.data_offset), data, read_size);
            len -= read_size;
            data += read_size;
            progress_update(&p, ubi->leb_size);
            if(len <= 0)
                break;
        }
        progress_stop(&p);
        return 0;
    }

    return -1;
}

int UbiVolumeCreate(ubi_t *ubi,  const char* name, int type, uint64_t size){
    int blks = (size + ubi->leb_size - 1)/ ubi->leb_size;
    int id = ubi_find_volume(ubi, name);
    
    if( id > 0){
        ubi_volume_t *volume = ubi->info->volume[id];
        if(blks != volume->reserved_pebs){
            printf("volume [%s] adjuest %d -> %d\n", name, volume->reserved_pebs, blks);
            volume->reserved_pebs = blks;
        }
    }else{
        printf("create volume [%s] %d\n", name, blks);
        id = ubi->info->volume_cnt;
        ubi->info->volume[id] = calloc(1, sizeof(ubi_volume_t));
        ubi_volume_t *volume = ubi->info->volume[id];
        strncpy(volume->name, name, UBI_VOL_NAME_MAX);
        volume->reserved_pebs = blks;
        volume->vol_type = type;
        ubi->info->volume_cnt++;
    }

    uint8_t *tbl = calloc(1, ubi->leb_size);
    for(int i = 0; i < UBI_MAX_VOLUME; i++){
        ubi_vol_tbl_record *vrec = (ubi_vol_tbl_record*)(tbl + sizeof(ubi_vol_tbl_record) * i);
        if(i < ubi->info->volume_cnt){
            ubi_volume_t *volume = ubi->info->volume[i];
            vrec->reserved_pebs = B32(volume->reserved_pebs);
            vrec->alignment = B32(1);
            strncpy((char*)vrec->name,  volume->name, UBI_VOL_NAME_MAX);
            vrec->name_len = B16(strlen(volume->name));
            vrec->vol_type = volume->vol_type;
        }
        vrec->crc = B32(JAMCRC(vrec, sizeof(ubi_vol_tbl_record) - 4));
    }

    ubi_ec_hdr ec;
    ubi_vid_hdr vid;

    int pnum = ubi->info->major_layout;
    if(ubi_get_ec_hdr(ubi, &ec, pnum)){
        if(ubi_get_vid_hdr(ubi, &vid, pnum, B32(ec.vid_hdr_offset))){
            ubi_erase_block(ubi, pnum * ubi->peb_size);
            ubi_write_block(ubi, pnum * ubi->peb_size, &ec, sizeof(ubi_ec_hdr));
            ubi_write_block(ubi, pnum * ubi->peb_size + B32(ec.vid_hdr_offset), &vid, sizeof(ubi_vid_hdr));
            ubi_write_block(ubi, pnum * ubi->peb_size + B32(ec.data_offset), tbl, ubi->leb_size);
        }
    }

    pnum = ubi->info->minor_layout;
    if(ubi_get_ec_hdr(ubi, &ec, pnum)){
        if(ubi_get_vid_hdr(ubi, &vid, pnum, B32(ec.vid_hdr_offset))){
            ubi_erase_block(ubi, pnum * ubi->peb_size);
            ubi_write_block(ubi, pnum * ubi->peb_size, &ec, sizeof(ubi_ec_hdr));
            ubi_write_block(ubi, pnum * ubi->peb_size + B32(ec.vid_hdr_offset), &vid, sizeof(ubi_vid_hdr));
            ubi_write_block(ubi, pnum * ubi->peb_size + B32(ec.data_offset), tbl, ubi->leb_size);
        }
    }
    return 0;
}

uint64_t UbiVolumeGetSize(ubi_t *ubi, char* name){
    ubi_volume_t* volume = ubi_get_volume(ubi, name);
    
    if( volume){
        return volume->reserved_pebs * ubi->leb_size;
    } else
        return 0;
}