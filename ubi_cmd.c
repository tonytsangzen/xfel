#include <fel.h>
#include <sha256.h>
#include <ecdsa256.h>
#include <spinor.h>
#include <spinand.h>
#include <ubi.h>
#include <libusb.h>

struct spinand_pdata_t pdat;
struct xfel_ctx_t * pctx;

#define NAND_PAGE_SIZE	2048
#define NAND_BLOCK_SIZE	(2*128*1024)

static size_t hum2digital(char* param){
    int multi = 1;
    char temp[64];
    char *p = temp;
    strncpy(temp, param, sizeof(temp));
    while(*p++ != 0){
        if(*p >= 0 && *p <= 9)
            continue;
        if(*p == 'K' || *p == 'k'){
            multi = 1024;
            *p = '\0';
            break;
        }
        if(*p == 'M' || *p == 'm'){
            multi = 1024*1024;
            *p = '\0';
            break;
        }
        if(*p == 'G' || *p == 'g'){
            multi = 1024*1024*1024;
            *p = '\0';
            break;
        }
    }
    return strtoul(temp, NULL, 0) * multi;
}


static uint64_t file_save(const char * filename, void * buf, uint64_t len)
{
	FILE * out = fopen(filename, "wb");
	int r;
	if(!out)
	{
		perror("Failed to open output file");
		exit(-1);
	}
	r = fwrite(buf, len, 1, out);
	fclose(out);
	return r;
}

static void * file_load(const char * filename, uint64_t * len)
{
	uint64_t offset = 0, bufsize = 8192;
	char * buf = malloc(bufsize);
	FILE * in;
	if(strcmp(filename, "-") == 0)
		in = stdin;
	else
		in = fopen(filename, "rb");
	if(!in)
	{
		perror("Failed to open input file");
		exit(-1);
	}
	while(1)
	{
		uint64_t len = bufsize - offset;
		uint64_t n = fread(buf + offset, 1, len, in);
		offset += n;
		if(n < len)
			break;
		bufsize *= 2;
		buf = realloc(buf, bufsize);
		if(!buf)
		{
			perror("Failed to resize load_file() buffer");
			exit(-1);
		}
	}
	if(len)
		*len = offset;
	if(in != stdin)
		fclose(in);
	return buf;
}

static void usage(void)
{
	printf("usage:\r\n");
	printf("    xfel ubi create <partition> <size>                   - create / adjuest ubi partition\r\n");
	printf("    xfel ubi write  <partition> <file>                   - Write image file to ubi partition\r\n");
	printf("    xfel ubi read   <partition> <file>                   - read image from to ubi partition\r\n");
	printf("    xfel ubi erase  <partition>                          - erase ubi partition\r\n");
}

static inline uint64_t PageAddrMap(uint64_t addr){
	int pnum = addr / NAND_BLOCK_SIZE; 
	int page = (addr % NAND_BLOCK_SIZE) / NAND_PAGE_SIZE; 
	int off = addr % NAND_PAGE_SIZE;

	//printf("%08x B:%d P:%d O:%d\n", addr, pnum, page, off);
	if(page % 2 == 0){
		return pnum * NAND_BLOCK_SIZE + page/2*NAND_PAGE_SIZE + off;
	}else{
		return pnum* NAND_BLOCK_SIZE + NAND_BLOCK_SIZE / 2 + page/2*NAND_PAGE_SIZE + off;
	}
}

static int nand_block_write(uint64_t addr, uint8_t *data, uint32_t size){
	int page = (size + NAND_PAGE_SIZE - 1)/NAND_PAGE_SIZE;
	for(int i = 0; i < page - 1; i++){
		spinand_helper_write(pctx, &pdat, PageAddrMap(addr), data, NAND_PAGE_SIZE);
		addr += NAND_PAGE_SIZE;
		data += NAND_PAGE_SIZE;
		size -= NAND_PAGE_SIZE;
	}
	if(size > 0){
		spinand_helper_write(pctx, &pdat, PageAddrMap(addr), data, size);
	}
	return  0;
}

static int nand_block_read(uint64_t addr, uint8_t *data, uint32_t size){
	int page = (size + NAND_PAGE_SIZE - 1)/NAND_PAGE_SIZE;
	for(int i = 0; i < page - 1; i++){
		spinand_helper_read(pctx, &pdat, PageAddrMap(addr), data, NAND_PAGE_SIZE);
		addr += NAND_PAGE_SIZE;
		data += NAND_PAGE_SIZE;
		size -= NAND_PAGE_SIZE;
	}
	if(size > 0){
		spinand_helper_read(pctx, &pdat, PageAddrMap(addr), data, size);
	}
	return 0;
}

static int nand_block_erase(uint64_t addr, uint32_t size){
	spinand_helper_erase(pctx, &pdat, addr, size);
	return 0;
}

ubi_io_t ubi_io ={
	.block_read = nand_block_read,
	.block_write = nand_block_write,
	.block_erase = nand_block_erase,
};


flash_info_t flash;

int nand_init(struct xfel_ctx_t * ctx){
	if(spinand_helper_init(ctx, &pdat)){
		flash.spare_size = pdat.info.spare_size;
		flash.page_size = pdat.info.page_size;
		flash.page_per_block = pdat.info.pages_per_block;
		flash.block_per_die = pdat.info.blocks_per_die;
		flash.ndies = pdat.info.ndies;
		return 1;
	}
	return 0;
}

int sub_ubi_cmd(struct xfel_ctx_t * ctx, int argc, char * argv[])
{
	pctx = ctx;
	ubi_t *ubi;

	if(!strcasecmp(argv[0],"read") && argc >= 3 && nand_init(ctx)){
		printf("ubi read volume [%s]\n", argv[1]);
		ubi = UbiInit(&ubi_io, &flash);
		uint64_t size = UbiVolumeGetSize(ubi, argv[1]);
		if(size){
			uint8_t *buf = malloc(size);
			UbiVolumeRead(ubi, argv[1],  buf, size);
			file_save(argv[2], buf, size);
			free(buf);
		}
	}else if(!strcasecmp(argv[0], "write") && argc >= 3 && nand_init(ctx)){
		printf("ubi write volume [%s]\n", argv[1]);
		uint64_t size;
		uint8_t* buf = file_load(argv[2], &size);
		if(size){
			ubi = UbiInit(&ubi_io, &flash);
			UbiVolumeWrite(ubi, argv[1],  buf, size);
			free(buf);
		}	
	}
	else if(!strcasecmp(argv[0], "erase")&& argc >= 2 && nand_init(ctx)){
		printf("ubi erase volume [%s]\n", argv[1]);
		ubi = UbiInit(&ubi_io, &flash);
		UbiVolumeErase(ubi, argv[1]);
	}else if(!strcasecmp(argv[0], "create")&& argc >= 3 && nand_init(ctx)){
		printf("ubi create volume [%s] %s\n", argv[1], argv[2]);
		ubi = UbiInit(&ubi_io, &flash);
		UbiVolumeCreate(ubi, argv[1], 2, hum2digital(argv[2]));
	}else{
		usage();
	}
	return 1;
}

