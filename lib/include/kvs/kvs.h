/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: Copyright (c) 2022 Laczen
 */

/**
 * @defgroup    kvs
 * @{
 * @brief       Key Value Store
 *
 * Generic key value store interface to store key-value items on different kind
 * of memory devices e.g. RAM, FLASH (nor or nand), EEPROM, ...
 *
 * Key-value items are stored as kvs entries consisting of a header, the key,
 * the value and a closing fill item that also ensures the entry is aligned to
 * the program size specified by the memory device. These entries are written
 * sequentially in blocks that have a configurable size. At the beginning of
 * each block a modified entry is written that contains some extra information.
 *
 * The configurable block size needs to be a power of 2. The block size limits
 * the maximum size of an entry as it needs to fit within one block.
 *
 */

#ifndef KVS_H_
#define KVS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KVS_MAGIC		  0x214b5653
#define KVS_MIN(a, b)		  (a < b ? a : b)
#define KVS_MAX(a, b)		  (a < b ? b : a)
#define KVS_ALIGNUP(num, align)	  (((num) + (align - 1)) & ~((align)-1))
#define KVS_ALIGNDOWN(num, align) ((num) & ~((align)-1))

#define KVS_CONTAINER_OF(ptr, type, field) ((type *)(((char *)(ptr)) - offsetof(type, field)))

/**
 * @brief KVS interface definition
 *
 */

/**
 * @brief KVS constant values
 *
 */
enum kvs_constants {
	KVS_HDRSTART = 0b10000000,
	KVS_HDRSTART_MASK = 0b11000000,
	KVS_FILLCHAR = 0b01100110,
	KVS_MAXHDRSIZE = 12,
	KVS_BUFSIZE = 16,
	KVS_INVALID_ADDR = 0xffffffff,
};

/**
 * @brief KVS error codes
 *
 */
enum kvs_error_codes {
	KVS_ENOENT = 2,	  /**< No such entry */
	KVS_EIO = 5,	  /**< I/O Error */
	KVS_EAGAIN = 11,  /**< No more contexts */
	KVS_EFAULT = 14,  /**< Bad address */
	KVS_EINVAL = 22,  /**< Invalid argument */
	KVS_ENOSPC = 28,  /**< No space left on device */
	KVS_EDEADLK = 45, /**< Resource deadlock avoided */
};

/**
 * @brief KVS entry structure
 *
 */
struct kvs_ent {
	uint32_t *kvs_id;   /**< pointer to the kvs_id in kvs */
	uint32_t start;	    /**< start position of the entry */
	uint32_t next;	    /**< position of the next entry */
	uint32_t ext_start; /**< start of extra (internal) data (from start) */
	uint32_t key_start; /**< start of key (from start)*/
	uint32_t val_start; /**< start of value data (from start)*/
	uint32_t val_len;   /**< val length */
};

/**
 * @brief KVS memory configuration definition
 *
 * This defines the functions provided to access the memory and os interface
 *
 */

struct kvs_cfg {
	const uint32_t bsize;	/**< block or sector size (byte) */
	const uint32_t bcnt;	/**< block count (including spare blocks) */
	const uint32_t bspr;	/**< spare block count */

	void *ctx;	      /**< opaque context pointer */
	void *pbuf;	      /**< pointer to prog buffer */
	const uint32_t psize; /**< size in byte of prog buffer */

	/**
	 * @brief read from memory device
	 *
	 * @param[in] ctx pointer to memory context
	 * @param[in] offset starting address
	 * @param[in] data pointer to buffer to place read data
	 * @param[in] len number of bytes
	 *
	 * @return 0 on success, -KVS_EIO on error.
	 */
	int (*read)(void *ctx, uint32_t offset, void *data, uint32_t len);

	/**
	 * @brief program memory device
	 *
	 * When writing to the first byte of a block this function should erase
	 * the blocks or set all bytes to 0xff/0x00 (on eeprom or ram).
	 *
	 * @param[in] ctx pointer to memory context
	 * @param[in] offset starting address
	 * @param[in] data pointer to data to be written
	 * @param[in] len number of bytes
	 *
	 * @return 0 on success, -KVS_EIO on error
	 */
	int (*prog)(void *ctx, uint32_t offset, const void *data, uint32_t len);

	/**
	 * @brief compare data to memory device content (optional)
	 *
	 * @param[in] ctx pointer to memory context
	 * @param[in] offset starting address
	 * @param[in] data pointer to data to be compared
	 * @param[in] len number of bytes
	 *
	 * @return 0 on success, -KVS_EIO on error
	 */
	int (*comp)(void *ctx, uint32_t offset, const void *data, uint32_t len);

	/**
	 * @brief memory device sync
	 *
	 * @param[in] ctx pointer to memory context
	 *
	 * @return 0 on success, error is propagated to user
	 */
	int (*sync)(void *ctx);

	/**
	 * @brief memory device init function
	 *
	 * @param[in] ctx pointer to memory context
	 *
	 * @return 0 on success, error is propagated to user
	 */
	int (*init)(void *ctx);

	/**
	 * @brief os provided lock function
	 *
	 * @param[in] ctx pointer to memory context
	 *
	 * @return 0 on success, error is propagated to user
	 */
	int (*lock)(void *ctx);

	/**
	 * @brief os provided unlock function
	 *
	 * @param[in] ctx pointer to memory context
	 *
	 * @return 0 on success, error is propagated to user
	 */
	int (*unlock)(void *ctx);
};

/**
 * @brief KVS data structure
 *
 */
struct kvs_data {
	uint32_t pos;		/**< current memory (write) position */
	uint32_t bend;		/**< current memory (write) block end */
	uint32_t epoch;		/**< current erase counter */
	struct kvs_ent *wr_ent; /**< pointer to write entry */
};

/**
 * @brief KVS structure
 *
 */
struct kvs {
	const uint32_t id;
	const struct kvs_cfg *cfg;
	struct kvs_data *data;	
};

/**
 * @brief Helper macro to define a kvs
 *
 */										
#define DEFINE_KVS(_name, _bsize, _bcnt, _bspr, _ctx, _pbuf, _psize, _read, _prog, _sync,	   \
		   _init, _lock, _unlock)							   \
	struct kvs_cfg _name##_kvs_cfg = {                                                         \
		.bsize = _bsize,								   \
		.bcnt = _bcnt,									   \
		.bspr = _bspr,									   \
		.ctx = &_ctx,                                                                      \
		.pbuf = &_pbuf,                                                                    \
		.psize = _psize,                                                                   \
		.read = _read,                                                                     \
		.prog = _prog,                                                                     \
		.sync = _sync,                                                                     \
		.init = _init,			                                                   \
		.lock = _lock,                                                                     \
		.unlock = _unlock,                                                                 \
	};											   \
	struct kvs_data _name##_kvs_data;							   \
	struct kvs _name##_kvs = {                                                                 \
		.cfg = &_name##_kvs_cfg,                                                           \
		.data = &_name##_kvs_data,                                                         \
	}

/**
 * @brief Helper macro to get a pointer to a KVS structure
 *
 */
#define GET_KVS(_name) &_name##_kvs

int kvs_compact(const struct kvs *kvs);
int kvs_mount(const struct kvs *kvs);
int kvs_unmount(const struct kvs *kvs);

int kvs_entry_get(struct kvs_ent *ent, const struct kvs *kvs, const char *key);
int kvs_entry_read(const struct kvs_ent *ent, uint32_t off, void *data, uint32_t len);

int kvs_read(const struct kvs *kvs, const char *key, void *data, uint32_t len);
int kvs_write(const struct kvs *kvs, const char *key, const void *data, uint32_t len);
int kvs_delete(const struct kvs *kvs, const char *key);

int kvs_walk(const struct kvs *kvs, const char *key,
	     int (*cb)(const struct kvs_ent *ent, void *arg), void *arg);
int kvs_walk_unique(const struct kvs *kvs, const char *key,
		    int (*cb)(const struct kvs_ent *ent, void *arg), void *arg);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* KVS_H_ */
/** @} */