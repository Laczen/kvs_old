/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: Copyright (c) 2022 Laczen
 */

/**
 * @defgroup    kvs
 * @{
 * @brief       Key Value Store
 *
 * Generic key value store interface to store and retrieve key-value items on
 * different kind of memory devices e.g. RAM, FLASH (nor or nand), EEPROM, ...
 *
 * Key-value items are stored as:
 *     byte 0: |. . . ... ..|
 *              | | |  |   |- value length bits 0-3: 1-4 value length byte
 *              | | |  |----- unused
 *              | | |-------- 1: includes value, 0 no value
 *              | |---------- 1: includes epoch counter, 0 no epoch counter
 *              |------------ odd parity bit (makes byte 1 odd parity)
 *     byte 1: key length (key length is limited to 255 bytes)
 *     byte 2-5: epoch counter (if included)
 *     byte 2-5 or 6-9: value length bytes.
 *     byte ... (key length): key bytes
 *     byte ... (value length): value bytes
 *     byte ... : fill bytes to meet alignment specified by the memory device
 *     byte ... : CRC32 value
 *
 * Items entries are written sequentially to blocks that have a configurable
 * size. At the beginning of each block a epoch counter is added to the entry.
 * The epoch counter is increased each time the memory wraps around. When a
 * new block is started the key value store verifies whether it needs to move
 * old entries to keep a copy and does so if required.
 *
 * The configurable block size needs to be a power of 2. The block size limits
 * the maximum size of an entry as it needs to fit within one block. The block
 * size is not limited to an erase block size of the memory device, this allows
 * using memory devices with non constant erase block sizes. However in this
 * last case carefull parameter selection is required to guarantee that there
 * will be no loss of data.
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

#define KVS_MIN(a, b)		  (a < b ? a : b)
#define KVS_MAX(a, b)		  (a < b ? b : a)
#define KVS_ALIGNUP(num, align)	  (((num) + (align - 1)) & ~((align)-1))
#define KVS_ALIGNDOWN(num, align) ((num) & ~((align)-1))

/**
 * @brief KVS interface definition
 *
 */

/**
 * @brief KVS constant values
 *
 */
enum kvs_constants
{
	KVS_PARITY_BITMASK = 0b10000000,
	KVS_EPOCH_BITMASK = 0b01000000,
	KVS_VALUE_BITMASK = 0b00100000,
	KVS_VALEN_BITMASK = 0b00000011,
	KVS_HDR_MINSIZE = 2,
	KVS_HDR_MAXSIZE = 10,
	KVS_EPOCHSIZE = 4,
	KVS_CRCSIZE = 4,
	KVS_FILLCHAR = 0b01100110,
	KVS_BUFSIZE = 16,
	KVS_KEY_MAXSIZE = 255,
};

/**
 * @brief KVS error codes
 *
 */
enum kvs_error_codes
{
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
	struct kvs *kvs;    /**< pointer to the kvs */
	uint32_t start;	    /**< start position of the entry */
	uint32_t next;	    /**< position of the next entry */
	uint32_t key_start; /**< start of key bytes (from start)*/
	uint32_t val_start; /**< start of value bytes (from start)*/
	uint32_t val_len;   /**< value length */
	uint32_t crc32;	    /**< crc32 calculated over the entry */
};

/**
 * @brief KVS memory configuration definition
 *
 * This defines the functions provided to access the memory and os interface
 *
 */

struct kvs_cfg {
	const uint32_t bsz;  /**< block or sector size (byte) */
	const uint32_t bcnt; /**< block count (including spare blocks) */
	const uint32_t bspr; /**< spare block count */

	void *ctx;	    /**< opaque context pointer */
	void *pbuf;	    /**< pointer to prog buffer */
	const uint32_t psz; /**< prog buffer size (byte) */

	/**
	 * @brief read from memory device
	 *
	 * @param[in] ctx pointer to memory context
	 * @param[in] off starting address
	 * @param[in] data pointer to buffer to place read data
	 * @param[in] len number of bytes
	 *
	 * @return 0 on success, -KVS_EIO on error.
	 */
	int (*read)(void *ctx, uint32_t off, void *data, uint32_t len);

	/**
	 * @brief program memory device
	 *
	 * When writing to the first byte of a block this function should erase
	 * the blocks or set all bytes to 0xff/0x00 (on eeprom or ram).
	 *
	 * @param[in] ctx pointer to memory context
	 * @param[in] off starting address
	 * @param[in] data pointer to data to be written
	 * @param[in] len number of bytes
	 *
	 * @return 0 on success, -KVS_EIO on error
	 */
	int (*prog)(void *ctx, uint32_t off, const void *data, uint32_t len);

	/**
	 * @brief compare data to memory device content (optional)
	 *
	 * @param[in] ctx pointer to memory context
	 * @param[in] off starting address
	 * @param[in] data pointer to data to be compared
	 * @param[in] len number of bytes
	 *
	 * @return 0 on success, -KVS_EIO on error
	 */
	int (*comp)(void *ctx, uint32_t off, const void *data, uint32_t len);

	/**
	 * @brief memory device sync
	 *
	 * @param[in] ctx pointer to memory context
	 * @param[in] off next writing address, passed to allow writing a end
	 *                marker to the backend (e.g. for eeprom).
	 *
	 * @return 0 on success, error is propagated to user
	 */
	int (*sync)(void *ctx, uint32_t off);

	/**
	 * @brief memory device init function
	 *
	 * @param[in] ctx pointer to memory context
	 *
	 * @return 0 on success, error is propagated to user
	 */
	int (*init)(void *ctx);

	/**
	 * @brief memory device release function
	 *
	 * @param[in] ctx pointer to memory context
	 *
	 * @return 0 on success, error is propagated to user
	 */
	int (*release)(void *ctx);

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
	 * @return 0 on success, error is ignored
	 */
	int (*unlock)(void *ctx);
};

/**
 * @brief KVS data structure
 *
 */
struct kvs_data {
	bool ready;
	uint32_t pos;	/**< current memory (write) position */
	uint32_t bend;	/**< current memory (write) block end */
	uint32_t epoch; /**< current erase counter */
};

/**
 * @brief KVS structure
 *
 */
struct kvs {
	const struct kvs_cfg *cfg;
	struct kvs_data *data;
};

/**
 * @brief Helper macro to define a kvs
 *
 */
#define DEFINE_KVS(_name, _bsz, _bcnt, _bspr, _ctx, _pbuf, _psz, _read, _prog, \
		   _comp, _sync, _init, _release, _lock, _unlock)              \
	struct kvs_cfg _name##_kvs_cfg = {                                     \
		.bsz = _bsz,                                                   \
		.bcnt = _bcnt,                                                 \
		.bspr = _bspr,                                                 \
		.ctx = _ctx,                                                   \
		.pbuf = _pbuf,                                                 \
		.psz = _psz,                                                   \
		.read = _read,                                                 \
		.prog = _prog,                                                 \
		.comp = _comp,                                                 \
		.sync = _sync,                                                 \
		.init = _init,                                                 \
		.release = _release,                                           \
		.lock = _lock,                                                 \
		.unlock = _unlock,                                             \
	};                                                                     \
	struct kvs_data _name##_kvs_data;                                      \
	struct kvs _name##_kvs = {                                             \
		.cfg = &_name##_kvs_cfg,                                       \
		.data = &_name##_kvs_data,                                     \
	}

/**
 * @brief Helper macro to get a pointer to a KVS structure
 *
 */
#define GET_KVS(_name) &_name##_kvs

/**
 * @brief mount the key value store
 *
 * @param[in] kvs pointer to key value store
 *
 * @return 0 on success, negative errorcode on error
 */
int kvs_mount(struct kvs *kvs);

/**
 * @brief unmount the key value store
 *
 * @param[in] kvs pointer to key value store
 *
 * @return 0 on success, negative errorcode on error
 */
int kvs_unmount(struct kvs *kvs);

/**
 * @brief compact the key value store (refreshes key value store and minimizes
 *        occupied flash).
 *
 * @param[in] kvs pointer to key value store
 *
 * @return 0 on success, negative errorcode on error
 */
int kvs_compact(const struct kvs *kvs);

/**
 * @brief get a entry from the key value store
 *
 * @param[out] ent pointer to the entry
 * @param[in] kvs pointer to key value store
 * @param[in] key key of the entry
 *
 * @return 0 on success, negative errorcode on error
 */
int kvs_entry_get(struct kvs_ent *ent, const struct kvs *kvs, const char *key);

/**
 * @brief read data from a entry in the kvs at offset
 *
 * @param[in] ent pointer to the entry
 * @param[in] off offset from entry start
 * @param[out] data
 * @param[in] len bytes to read
 *
 * @return 0 on success, negative errorcode on error
 */
int kvs_entry_read(const struct kvs_ent *ent, uint32_t off, void *data,
		   uint32_t len);

/**
 * @brief read value for a key in the kvs
 *
 * @param[in] kvs pointer to the kvs
 * @param[in] key
 * @param[out] value
 * @param[in] len value length (bytes)
 *
 * @return 0 on success, negative errorcode on error
 */
int kvs_read(const struct kvs *kvs, const char *key, void *value, uint32_t len);

/**
 * @brief write value for a key in the kvs
 *
 * @param[in] kvs pointer to the kvs
 * @param[in] key
 * @param[in] value
 * @param[in] len value length (bytes)
 *
 * @return 0 on success, negative errorcode on error
 */
int kvs_write(const struct kvs *kvs, const char *key, const void *value,
	      uint32_t len);

/**
 * @brief delete a key in the kvs
 *
 * @param[in] kvs pointer to the kvs
 * @param[in] key
 *
 * @return 0 on success, negative errorcode on error
 */
int kvs_delete(const struct kvs *kvs, const char *key);

/**
 * @brief walk over entries in kvs and issue a cb for each entry that starts
 *        with the specified key
 *
 * @param[in] kvs pointer to the kvs
 * @param[in] key
 * @param[in] cb callback function
 * @param[in] arg callback function argument
 *
 * @return 0 on success, negative errorcode on error
 */
int kvs_walk(const struct kvs *kvs, const char *key,
	     int (*cb)(const struct kvs_ent *ent, void *arg), void *arg);

/**
 * @brief walk over entries in kvs and issue a cb for each entry that starts
 *        with the specified key, the cb is only called for the last added
 *	  entry.
 *
 * @param[in] kvs pointer to the kvs
 * @param[in] key
 * @param[in] cb callback function
 * @param[in] arg callback function argument
 *
 * @return 0 on success, negative errorcode on error
 */
int kvs_walk_unique(const struct kvs *kvs, const char *key,
		    int (*cb)(const struct kvs_ent *ent, void *arg), void *arg);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* KVS_H_ */
       /** @} */