#ifndef __SPINAND_H__
#define __SPINAND_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <fel.h>

struct spinand_info_t {
	char * name;
	struct {
		uint8_t val[4];
		uint8_t len;
	} id;
	uint32_t page_size;
	uint32_t spare_size;
	uint32_t pages_per_block;
	uint32_t blocks_per_die;
	uint32_t planes_per_die;
	uint32_t ndies;
};

struct spinand_pdata_t {
	struct spinand_info_t info;
	uint32_t swapbuf;
	uint32_t swaplen;
	uint32_t cmdlen;
};

int spinand_helper_init(struct xfel_ctx_t * ctx, struct spinand_pdata_t * pdat);
void spinand_helper_read(struct xfel_ctx_t * ctx, struct spinand_pdata_t * pdat, uint32_t addr, uint8_t * buf, uint32_t count);
void spinand_helper_erase(struct xfel_ctx_t * ctx, struct spinand_pdata_t * pdat, uint64_t addr, uint64_t count);
void spinand_helper_write(struct xfel_ctx_t * ctx, struct spinand_pdata_t * pdat, uint32_t addr, uint8_t * buf, uint32_t count);

int spinand_detect(struct xfel_ctx_t * ctx, char * name, uint64_t * capacity);
int spinand_erase(struct xfel_ctx_t * ctx, uint64_t addr, uint64_t len);
int spinand_read(struct xfel_ctx_t * ctx, uint64_t addr, void * buf, uint64_t len);
int spinand_write(struct xfel_ctx_t * ctx, uint64_t addr, void * buf, uint64_t len);
int spinand_splwrite(struct xfel_ctx_t * ctx, uint32_t splitsz, uint64_t addr, void * buf, uint64_t len);

#ifdef __cplusplus
}
#endif

#endif /* __SPINAND_H__ */
