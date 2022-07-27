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
	KVS_ENOENT = 2,         /**< No such entry */
	KVS_EIO = 5,            /**< I/O Error */
        KVS_EAGAIN = 11,        /**< No more contexts */
	KVS_EINVAL = 22,        /**< Invalid argument */
	KVS_ENOSPC = 28,        /**< No space left on device */
	KVS_EDEADLK = 45,       /**< Resource deadlock avoided */
};

/**
 * @brief KVS entry structure
 *
 */
struct kvs_ent {
	uint32_t *pos;	    /**< pointer to the pos location in kvs_fs */
	uint32_t start;	    /**< start position of the entry */
	uint32_t next;	    /**< position of the next entry */
	uint32_t ext_start; /**< start of extra (internal) data (from start) */
	uint32_t key_start; /**< start of key (from start)*/
	uint32_t val_start; /**< start of value data (from start)*/
	uint32_t val_len;   /**< val length */
};

/**
 * @brief KVS configuration definition
 * 
 * This defines the functions provided to access the memory and os interface
 *
 */

struct kvs_fs_cfg {
	void *ctx;              /**< opaque context pointer */
	void *pbuf;             /**< pointer to prog buffer */
	const uint32_t psize;   /**< size in byte of prog buffer */
	
	/**
	 * @brief read from memory device
         * 
         * @param[in] ctx pointer to memory context
         * @param[in] offset starting address
         * @param[in] data pointer to buffer to place read data
         * @param[in] len number of bytes 
	 * 
         * @return 0 on success, < 0 on error
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
         * @return 0 on success, < 0 on error 
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
         * @return 0 on success, < 0 on error
         */
	int (*comp)(void *ctx, uint32_t offset, const void *data, uint32_t len);
	
        /**
         * @brief memory device sync
         * 
         * @param[in] ctx pointer to memory context
         * 
         * @return 0 on success, < 0 on error
         */
	int (*sync)(void *ctx);

	/**
         * @brief check if memory area is writable (in erased state)
         * 
         * @param[in] ctx pointer to memory context
         * @param[in] offset starting address
         * @param[in] len number of bytes
         * 
         * @return true if writable, false if not writable
         */
        bool (*is_writable)(void *ctx, uint32_t offset, uint32_t len);
	
        /**
         * @brief memory device init function
         * 
         * @param[in] ctx pointer to memory context
         * 
         * @return 0 on success, < 0 on error
         */
	int (*init)(void *ctx);

        /**
         * @brief os provided lock function
         * 
         * @param[in] ctx pointer to memory context
         * 
         * @return 0 on success, < 0 on error
         */
	int (*lock)(void *ctx);

        /**
         * @brief os provided unlock function
         * 
         * @param[in] ctx pointer to memory context
         * 
         * @return 0 on success, < 0 on error
         */
	int (*unlock)(void *ctx);

        /**
         * @brief hash function
         * 
         * @param[in] key input for hash
         * @param[in] len key length
         * @param[in] hash previous hash value (allows hash update)
         * 
         * @return calculated hash
         */
	uint32_t (*hash)(const void *key, uint32_t len, uint32_t hash);
	
        /**
         * @brief return the block address a hash is pointing to
         * 
         * @param[in] hash
         * 
         * @return block address
         */
        uint32_t (*hash_get_block_addr)(uint32_t hash);

        /**
         * @brief set the block address for a hashpointing to
         * 
         * @param[in] hash
         * @param[in] block_addr block address
         */
	void (*hash_set_block_addr)(uint32_t hash, uint32_t block_addr);

        /**
         * @brief initialize all block addresses in the hash table with an
         * invalid value
         * 
         * @param[in] block_addr (invalid) block address
         */
	void (*hash_init_block_addr)(uint32_t block_addr);
};

/**
 * @brief Helper macro to define a kvs configuration
 * 
 */
#define DEFINE_KVS_CFG(_name, _ctx, _pbuf, _psize, _read, _prog, _sync, _is_writable, _lock,       \
		       _unlock, _hash, _hash_get_addr, _hash_set_addr, _hash_init_addr)            \
	struct kvs_fs_cfg _name##_kvs_cfg = {                                                      \
		.ctx = &_ctx,                                                                      \
		.pbuf = &_pbuf,                                                                    \
		.psize = _psize,                                                                   \
		.read = _read,                                                                     \
		.prog = _prog,                                                                     \
		.sync = _sync,                                                                     \
		.is_writable = _is_writable,                                                       \
		.lock = _lock,                                                                     \
		.unlock = _unlock,                                                                 \
		.hash = _hash,                                                                     \
		.hash_get_addr = _hash_get_addr,                                                   \
		.hash_set_addr = _hash_set_addr,                                                   \
		.hash_init_addr = _hash_init_addr,                                                 \
	}

/**
 * @brief Helper macro to get a pointer to a KVS configuration
 * 
 */
#define GET_KVS_CFG(_name) &_name##_kvs_cfg

/**
 * @brief KVS structure
 * 
 */
struct kvs_fs {
	const struct kvs_fs_cfg *cfg;
	const uint32_t bsize;	/* block or sector size (byte) */
	const uint32_t bcnt;	/* block count (including spare blocks) */
	uint32_t bspr;		/* spare block count */
	uint32_t epoch;		/* current erase counter */
	uint32_t pos;		/* current memory (write) position */
	uint32_t bend;		/* current memory (write) block end */
	struct kvs_ent *wr_ent; /* pointer to write entry */
};

/**
 * @brief Helper macro to define a KVS structure
 * 
 */
#define DEFINE_KVS(_name, _bsize, _bcnt, _bspr)                                                    \
	struct kvs_fs _name##_kvs_fs = {                                                           \
		.cfg = GET_KVS_CFG(_name),                                                         \
		.bsize = _bsize,                                                                   \
		.bcnt = _bcnt,                                                                     \
		.bspr = _bspr,                                                                     \
		.epoch = 0U,                                                                       \
		.pos = 0U,                                                                         \
		.bend = _bsize,                                                                    \
		.wrt_ent = NULL,                                                                   \
	}

/**
 * @brief Helper macro to get a pointer to a KVS structure
 * 
 */
#define GET_KVS(_name) &_name##_kvs_fs


int kvs_mount(const struct kvs_fs *fs);
int kvs_unmount(const struct kvs_fs *fs);
int kvs_compact(const struct kvs_fs *fs);
int kvs_init_hash_table(const struct kvs_fs *fs);

int kvs_entry_add(struct kvs_ent *ent, struct kvs_fs *fs, const char *key, uint32_t val_len);
int kvs_entry_flush(struct kvs_ent *ent);
int kvs_entry_get(struct kvs_ent *ent, const struct kvs_fs *fs, const char *key);

int kvs_entry_read(const struct kvs_ent *ent, uint32_t off, void *data, uint32_t len);
int kvs_entry_write(struct kvs_ent *ent, uint32_t off, const void *data, uint32_t len);

int kvs_read(const struct kvs_fs *kvs_fs, const char *key, void *data, uint32_t len);
int kvs_write(const struct kvs_fs *kvs_fs, const char *key, const void *data, uint32_t len);

int kvs_walk(const struct kvs_fs *kvs_fs, const char *key, int (*cb)(const struct kvs_ent *ent));
int kvs_walk_unique(const struct kvs_fs *kvs_fs, const char *key,
		    int (*cb)(const struct kvs_ent *ent));

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* KVS_H_ */
/** @} */