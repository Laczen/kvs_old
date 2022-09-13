/*
 * Key Value Store
 *
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "kvs/kvs.h"

#include <string.h>

#include <zephyr/sys/printk.h>

static int kvs_dev_init(const struct kvs *kvs)
{
	const struct kvs_cfg *cfg = kvs->cfg;

	if (cfg->init == NULL) {
		return 0;
	}

	return cfg->init(cfg->ctx);
}

static int kvs_dev_release(const struct kvs *kvs)
{
	const struct kvs_cfg *cfg = kvs->cfg;

	if (cfg->release == NULL) {
		return 0;
	}

	return cfg->release(cfg->ctx);
}

static int kvs_dev_lock(const struct kvs *kvs)
{
	const struct kvs_cfg *cfg = kvs->cfg;

	if (cfg->lock == NULL) {
		return 0;
	}

	return cfg->lock(cfg->ctx);
}

static int kvs_dev_unlock(const struct kvs *kvs)
{
	const struct kvs_cfg *cfg = kvs->cfg;

	if (cfg->unlock == NULL) {
		return 0;
	}

	return cfg->unlock(cfg->ctx);
}

static int kvs_dev_sync(const struct kvs *kvs)
{
	const struct kvs_cfg *cfg = kvs->cfg;

	if (cfg->sync == NULL) {
		return 0;
	}

	return cfg->sync(cfg->ctx, kvs->data->pos);
}

static int kvs_dev_read(const struct kvs *kvs, uint32_t off, void *data,
			uint32_t len)
{
	const struct kvs_cfg *cfg = kvs->cfg;

	return cfg->read(cfg->ctx, off, data, len);
}

static int kvs_dev_prog(const struct kvs *kvs, uint32_t off, const void *data,
			uint32_t len)
{
	const struct kvs_cfg *cfg = kvs->cfg;

	return cfg->prog(cfg->ctx, off, data, len);
}

static int kvs_dev_comp(const struct kvs *kvs, uint32_t off, const void *data,
			uint32_t len)
{
	const struct kvs_cfg *cfg = kvs->cfg;

	if (cfg->comp == NULL) {
		return 0;
	}

	return cfg->comp(cfg->ctx, off, data, len);
}

static uint32_t kvs_crc32(uint32_t crc, const void *buf, size_t len)
{
	const uint8_t *data = (const uint8_t *)buf;
	/* crc table generated from polynomial 0xedb88320 */
	static const uint32_t table[16] = {
		0x00000000U, 0x1db71064U, 0x3b6e20c8U, 0x26d930acU,
		0x76dc4190U, 0x6b6b51f4U, 0x4db26158U, 0x5005713cU,
		0xedb88320U, 0xf00f9344U, 0xd6d6a3e8U, 0xcb61b38cU,
		0x9b64c2b0U, 0x86d3d2d4U, 0xa00ae278U, 0xbdbdf21cU,
	};

	crc = ~crc;

	for (size_t i = 0; i < len; i++) {
		uint8_t byte = data[i];

		crc = (crc >> 4) ^ table[(crc ^ byte) & 0x0f];
		crc = (crc >> 4) ^ table[(crc ^ (byte >> 4)) & 0x0f];
	}

	return (~crc);
}

static bool ehdr_has_odd_parity(const uint8_t *hdr)
{
	uint8_t byte = hdr[0];

	byte ^= (byte >> 4);
	byte &= 0xf;
	return ((0x6996 >> byte) & 1U) == 1U;
}

static void ehdr_set_odd_parity(uint8_t *hdr)
{
	if (!ehdr_has_odd_parity(hdr)) {
		*hdr ^= KVS_PARITY_BITMASK;
	}
}

/* value length byte count from entry header */
static uint32_t ehdr_vlbc(const uint8_t *hdr)
{
	if ((*hdr & KVS_VALUE_BITMASK) == 0U) {
		return 0U;
	}

	return 1U + ((*hdr) & KVS_VALEN_BITMASK);
}

/* epoch byte count from entry header */
static uint32_t ehdr_epbc(const uint8_t *hdr)
{
	if ((*hdr & KVS_EPOCH_BITMASK) == 0U) {
		return 0U;
	}

	return KVS_EPOCHSIZE;
}

/* entry header size from entry header */
static uint32_t ehdr_len(const uint8_t *hdr)
{
	return KVS_HDR_MINSIZE + ehdr_epbc(hdr) + ehdr_vlbc(hdr);
}

static void ehdr2entry(const uint8_t *hdr, struct kvs_ent *ent)
{
	const uint32_t vlbc_offset = KVS_HDR_MINSIZE + ehdr_epbc(hdr);

	ent->key_start = ehdr_len(hdr);
	ent->val_start = ent->key_start + hdr[1];
	ent->val_len = 0;

	for (uint32_t i = 0; i < ehdr_vlbc(hdr); i++) {
		ent->val_len += (hdr[vlbc_offset + i] << (8 * i));
	}
}

static int ehdr_get_epoch(const uint8_t *hdr, uint32_t *epoch)
{
	if ((hdr[0] & KVS_EPOCH_BITMASK) != KVS_EPOCH_BITMASK) {
		return -KVS_ENOENT;
	}

	*epoch = (uint32_t)hdr[2] + (uint32_t)(hdr[3] << 8) +
		 (uint32_t)(hdr[4] << 16) + (uint32_t)(hdr[5] << 24);
	return 0;
}

static void ehdr_add_klen(uint8_t *hdr, const uint8_t klen)
{
	hdr[1] = klen;
}

static void ehdr_add_epoch(uint8_t *hdr, const uint32_t epoch)
{
	hdr[0] |= KVS_EPOCH_BITMASK;
	hdr[2] = (uint8_t)(epoch & 0xff);
	hdr[3] = (uint8_t)((epoch >> 8) & 0xff);
	hdr[4] = (uint8_t)((epoch >> 16) & 0xff);
	hdr[5] = (uint8_t)((epoch >> 24) & 0xff);
}

static void ehdr_add_vlen(uint8_t *hdr, uint32_t val_len)
{
	uint32_t vlbc_offset = KVS_HDR_MINSIZE + ehdr_epbc(hdr);

	if (val_len == 0U) {
		hdr[0] &= ~KVS_VALUE_BITMASK;
	}

	hdr[0] |= KVS_VALUE_BITMASK;

	while (true) {
		hdr[vlbc_offset++] = (uint8_t)(val_len & 0xff);
		val_len >>= 8;
		if (val_len == 0U) {
			break;
		}

		hdr[0]++;
	}
}

static uint32_t ehdr_make(const struct kvs_ent *ent, uint8_t *hdr)
{
	const struct kvs *kvs = ent->kvs;
	const uint32_t bsz = kvs->cfg->bsz;
	struct kvs_data *data = kvs->data;

	hdr[0] = KVS_PARITY_BITMASK;
	ehdr_add_klen(hdr, (uint8_t)(ent->val_start - ent->key_start));
	if (data->pos == KVS_ALIGNDOWN(data->pos, bsz)) {
		ehdr_add_epoch(hdr, data->epoch);
	}

	ehdr_add_vlen(hdr, ent->val_len);
	ehdr_set_odd_parity(hdr);

	return ehdr_len(hdr);
}

static int entry_read(const struct kvs_ent *ent, uint32_t off, void *data,
		      uint32_t len)
{
	const struct kvs *kvs = ent->kvs;

	len = KVS_MIN(len, ent->next - (ent->start + off));
	return kvs_dev_read(kvs, ent->start + off, data, len);
}

static int entry_raw_write(const struct kvs_ent *ent, uint32_t off,
			   const void *data, uint32_t len)
{
	const struct kvs *kvs = ent->kvs;
	const struct kvs_cfg *cfg = kvs->cfg;
	const uint32_t psz = cfg->psz;
	const uint32_t rem = KVS_ALIGNUP(off, psz) - off;
	uint8_t *pbuf8 = (uint8_t *)cfg->pbuf;
	uint8_t *data8 = (uint8_t *)data;
	int rc = 0;

	if ((ent->next - ent->start) < (off + len)) {
		return -KVS_EINVAL;
	}

	if ((data == NULL) || (len == 0U)) {
		return 0;
	}

	off = ent->start + KVS_ALIGNDOWN(off, psz);

	/* fill remaining part of program buffer and write if needed */
	if (rem != 0) {
		const uint32_t wrlen = KVS_MIN(len, rem);
		uint8_t *buf = pbuf8 + (psz - rem);

		memcpy(buf, data8, wrlen);
		if (wrlen == rem) {
			rc = kvs_dev_prog(kvs, off, pbuf8, psz);
			if (rc != 0) {
				goto end;
			}

			rc = kvs_dev_comp(kvs, off, pbuf8, psz);
			if (rc != 0) {
				goto end;
			}

			off += psz;
		}

		data8 += wrlen;
		len -= wrlen;
	}

	/* perform direct write if possible */
	if (len >= psz) {
		uint32_t wrlen = KVS_ALIGNDOWN(len, psz);

		rc = kvs_dev_prog(kvs, off, data8, wrlen);
		if (rc != 0) {
			goto end;
		}

		rc = kvs_dev_comp(kvs, off, data8, wrlen);
		if (rc != 0) {
			goto end;
		}

		data8 += wrlen;
		len -= wrlen;
	}

	/* add remaining part to program buffer */
	if (len != 0U) {
		memcpy(pbuf8, data8, len);
	}

	return 0;
end:
	/* write failure has occured - advance kvs->data->pos to block end */
	kvs->data->pos = kvs->data->bend;
	return rc;
}

struct read_cb {
	const void *ctx;
	uint32_t off;
	uint32_t len;
	int (*read)(const void *ctx, uint32_t off, void *data, uint32_t len);
};

static int read_cb_entry(const void *ctx, uint32_t off, void *data,
			 uint32_t len)
{
	struct kvs_ent *ent = (struct kvs_ent *)(ctx);

	return entry_read(ent, off, data, len);
}

static int read_cb_ptr(const void *ctx, uint32_t off, void *data, uint32_t len)
{
	uint8_t *src = (uint8_t *)ctx;

	memcpy(data, src + off, len);
	return 0;
}

static bool key_starts_with(const struct kvs_ent *ent, const struct read_cb *rd)
{
	if (rd->len > (ent->val_start - ent->key_start)) {
		return false;
	}

	uint8_t bufe[KVS_BUFSIZE], bufr[KVS_BUFSIZE];
	uint32_t len = rd->len;
	uint32_t off = 0U;
	int rc;

	while (len != 0U) {
		uint32_t rdlen = KVS_MIN(len, KVS_BUFSIZE);

		rc = entry_read(ent, ent->key_start + off, bufe, rdlen);
		if (rc != 0) {
			return false;
		}

		rc = rd->read(rd->ctx, rd->off + off, bufr, rdlen);
		if (rc != 0) {
			return false;
		}

		if (memcmp(bufe, bufr, rdlen) != 0) {
			return false;
		}

		off += rdlen;
		len -= rdlen;
	}

	return true;
}

static void wblock_advance(const struct kvs *kvs)
{
	const struct kvs_cfg *cfg = kvs->cfg;
	struct kvs_data *data = kvs->data;

	data->pos = data->bend;
	if (data->pos == (cfg->bcnt * cfg->bsz)) {
		data->epoch++;
		data->pos = 0U;
	}

	data->bend = data->pos + cfg->bsz;
}

static void entry_link(struct kvs_ent *ent, const struct kvs *kvs)
{
	ent->kvs = (struct kvs *)kvs;
}

static int entry_write(struct kvs_ent *ent, uint32_t off, const void *data,
		       uint32_t len)
{
	ent->crc32 = kvs_crc32(ent->crc32, data, len);
	return entry_raw_write(ent, off, data, len);
}

static int entry_write_hdr(struct kvs_ent *ent, uint32_t key_len,
			   uint32_t val_len)
{
	const struct kvs *kvs = ent->kvs;
	const uint32_t psz = kvs->cfg->psz;
	struct kvs_data *data = kvs->data;
	uint8_t hdr[KVS_HDR_MAXSIZE];
	uint32_t hdr_len, entry_len;

	ent->crc32 = 0U;
	ent->key_start = 0U;
	ent->val_start = key_len;
	ent->val_len = val_len;
	hdr_len = ehdr_make(ent, hdr);
	ent->key_start += hdr_len;
	ent->val_start += hdr_len;

	entry_len = ent->val_start + ent->val_len + KVS_CRCSIZE;
	entry_len = KVS_ALIGNUP(entry_len, psz);
	if (entry_len > (data->bend - data->pos)) {
		return -KVS_ENOSPC;
	}

	ent->start = data->pos;
	ent->next = ent->start + entry_len;
	data->pos = ent->next;

	return entry_write(ent, 0, hdr, hdr_len);
}

static int entry_write_crc(struct kvs_ent *ent)
{
	const uint32_t tlen = ent->next - ent->start - KVS_CRCSIZE;
	const uint8_t fill = KVS_FILLCHAR;
	uint32_t off = ent->val_start + ent->val_len;
	int rc;

	while (off < tlen) {
		rc = entry_raw_write(ent, off, &fill, 1);
		if (rc) {
			return rc;
		}

		off++;
	}

	return entry_raw_write(ent, off, &ent->crc32, KVS_CRCSIZE);
}

static int entry_write_data(struct kvs_ent *ent, uint32_t dstart,
			    const struct read_cb *drd_cb)
{
	uint32_t len, off;
	uint8_t buf[KVS_BUFSIZE];
	int rc;

	len = drd_cb->len;
	off = 0U;
	while (len != 0) {
		uint32_t rwlen = KVS_MIN(len, sizeof(buf));
		rc = drd_cb->read(drd_cb->ctx, drd_cb->off + off, buf, rwlen);
		if (rc != 0) {
			return rc;
		}

		rc = entry_write(ent, dstart + off, buf, rwlen);
		if (rc != 0) {
			return rc;
		}

		off += rwlen;
		len -= rwlen;
	}

	return 0;
}

static int entry_append(struct kvs_ent *ent, const struct read_cb *krd_cb,
			const struct read_cb *vrd_cb)
{
	int rc;

	rc = entry_write_hdr(ent, krd_cb->len, vrd_cb->len);
	if (rc != 0) {
		return rc;
	}

	rc = entry_write_data(ent, ent->key_start, krd_cb);
	if (rc != 0) {
		goto end;
	}

	rc = entry_write_data(ent, ent->val_start, vrd_cb);
	if (rc != 0) {
		goto end;
	}

	rc = entry_write_crc(ent);
	if (rc != 0) {
		goto end;
	}

	rc = kvs_dev_sync(ent->kvs);
end:
	return rc;
}

static int entry_add(struct kvs_ent *ent, const char *key, const void *value,
		     uint32_t val_len)
{
	const struct read_cb krd_cb = {
		.ctx = (void *)key,
		.off = 0U,
		.len = KVS_MIN(strlen(key), KVS_KEY_MAXSIZE),
		.read = read_cb_ptr,
	};
	const struct read_cb vrd_cb = {
		.ctx = (void *)value,
		.off = 0U,
		.len = val_len,
		.read = read_cb_ptr,
	};

	return entry_append(ent, &krd_cb, &vrd_cb);
}

static int entry_copy(const struct kvs_ent *ent)
{
	const struct read_cb krd_cb = {
		.ctx = (void *)ent,
		.off = ent->key_start,
		.len = ent->val_start - ent->key_start,
		.read = read_cb_entry,
	};
	const struct read_cb vrd_cb = {
		.ctx = (void *)ent,
		.off = ent->val_start,
		.len = ent->val_len,
		.read = read_cb_entry,
	};
	struct kvs_ent cp_ent;

	entry_link(&cp_ent, ent->kvs);
	return entry_append(&cp_ent, &krd_cb, &vrd_cb);
}

static int entry_crc32_verify(struct kvs_ent *ent)
{
	uint32_t len, off, crc32, crc32r;
	uint8_t buf[KVS_BUFSIZE];
	int rc;

	len = ent->val_start + ent->val_len;
	off = 0U;
	crc32 = 0U;
	while (len != 0U) {
		uint32_t rdlen = KVS_MIN(len, sizeof(buf));
		rc = entry_read(ent, off, buf, rdlen);
		if (rc != 0U) {
			goto end;
		}
		crc32 = kvs_crc32(crc32, buf, rdlen);
		off += rdlen;
		len -= rdlen;
	}

	off = ent->next - ent->start - KVS_CRCSIZE;
	rc = entry_read(ent, off, &crc32r, KVS_CRCSIZE);
	if (rc != 0) {
		goto end;
	}

	if (crc32 != crc32r) {
		rc = -KVS_EIO;
	}

end:
	return rc;
}

static int entry_get_info(struct kvs_ent *ent)
{
	const struct kvs *kvs = ent->kvs;
	const struct kvs_cfg *cfg = kvs->cfg;
	const uint32_t psz = cfg->psz;
	uint8_t hdr[KVS_HDR_MAXSIZE];
	uint32_t esz;
	int rc;

	ent->next = KVS_ALIGNDOWN(ent->start, cfg->bsz) + cfg->bsz;
	rc = entry_read(ent, 0, hdr, sizeof(hdr));
	if (rc != 0) {
		goto end;
	}

	if (!ehdr_has_odd_parity(hdr)) {
		goto end;
	}

	ehdr2entry(hdr, ent);
	esz = KVS_ALIGNUP(ent->val_start + ent->val_len + KVS_CRCSIZE, psz);
	ent->next = ent->start + esz;
	rc = entry_crc32_verify(ent);
	if (rc != 0) {
		goto end;
	}

	return rc;
end:
	return -KVS_ENOENT;
}

static int entry_match_in_block(struct kvs_ent *ent,
				bool (*match)(const struct kvs_ent *ent,
					      void *arg),
				void *arg)
{
	const struct kvs *kvs = ent->kvs;
	const uint32_t bsz = kvs->cfg->bsz;
	const uint32_t psz = kvs->cfg->psz;
	uint32_t bend = KVS_ALIGNDOWN(ent->start, bsz) + bsz;

	if (bend == kvs->data->bend) {
		bend = kvs->data->pos;
	}

	while (ent->next < bend) {
		ent->start = ent->next;
		if (entry_get_info(ent) != 0) {
			ent->next = ent->start + psz;
			continue;
		}

		if (match == NULL) {
			return 0;
		}

		if (match(ent, arg)) {
			return 0;
		}
	}

	return -KVS_ENOENT;
}

static int entry_zigzag_walk(struct kvs_ent *ent,
			     bool (*match)(const struct kvs_ent *ent,
					   void *arg),
			     void *arg)
{
	const struct kvs *kvs = ent->kvs;
	const struct kvs_cfg *cfg = kvs->cfg;
	const struct kvs_data *data = kvs->data;
	const uint32_t bsz = cfg->bsz;
	const uint32_t bcnt = cfg->bcnt;
	const uint32_t end = bsz * bcnt;
	bool found = false;
	struct kvs_ent wlk;

	entry_link(&wlk, kvs);
	wlk.next = data->bend - bsz;

	for (int i = 0; i < bcnt; i++) {
		wlk.start = wlk.next;
		while (entry_match_in_block(&wlk, match, arg) == 0) {
			found = true;
			memcpy(ent, &wlk, sizeof(struct kvs_ent));
		}

		if (found) {
			break;
		}

		wlk.next = KVS_ALIGNDOWN(wlk.start, bsz);
		if (wlk.next == 0U) {
			wlk.next = end;
		}

		wlk.next -= bsz;
	}

	if (found) {
		return 0;
	}

	return -KVS_ENOENT;
}

static bool match_key_start(const struct kvs_ent *ent, void *cb_arg)
{
	struct read_cb *arg = (struct read_cb *)cb_arg;

	if ((arg->len == 0U) || (arg->ctx == NULL)) {
		return true;
	}

	if (key_starts_with(ent, cb_arg)) {
		return true;
	}

	return false;
}

static bool match_key_exact(const struct kvs_ent *ent, void *cb_arg)
{
	struct read_cb *arg = (struct read_cb *)cb_arg;

	if ((ent->val_start - ent->key_start) != arg->len) {
		return false;
	}

	return match_key_start(ent, cb_arg);
}

static int entry_get(struct kvs_ent *ent, const struct kvs *kvs,
		     const struct read_cb *rdkey)
{
	entry_link(ent, kvs);

	if (entry_zigzag_walk(ent, match_key_exact, (void *)rdkey) == 0) {
		return 0;
	}

	return -KVS_ENOENT;
}

static int entry_from_key(struct kvs_ent *ent, const struct kvs *kvs,
			  const char *key)
{
	const struct read_cb rdkey = {
		.ctx = (void *)key,
		.len = strlen(key),
		.off = 0U,
		.read = read_cb_ptr,
	};

	return entry_get(ent, kvs, &rdkey);
}

struct entry_cb {
	void *cb_arg;
	int (*cb)(const struct kvs_ent *entry, void *cb_arg);
};

static int entry_walk(const struct kvs *kvs, const struct read_cb *rd,
		      const struct entry_cb *cb, uint32_t bcnt)
{
	const struct kvs_cfg *cfg = kvs->cfg;
	const struct kvs_data *data = kvs->data;
	const uint32_t end = cfg->bcnt * cfg->bsz;
	struct kvs_ent wlk;
	int rc;

	entry_link(&wlk, kvs);
	wlk.next = (data->bend < end) ? data->bend : 0U;
	for (int i = 0; i < bcnt; i++) {
		wlk.start = wlk.next;
		while (entry_match_in_block(&wlk, match_key_start,
					    (void *)rd) == 0) {
			rc = cb->cb(&wlk, cb->cb_arg);
			if (rc != 0) {
				goto end;
			}
		}
		wlk.next = (wlk.next < end) ? wlk.next : 0U;
	}
end:
	return rc;
}

static int unique_walk_cb(const struct kvs_ent *ent, void *cb_arg)
{
	const struct entry_cb *cb = (struct entry_cb *)cb_arg;
	const struct read_cb rdkey = {
		.ctx = (void *)ent,
		.len = ent->val_start - ent->key_start,
		.off = ent->key_start,
		.read = read_cb_entry,
	};
	struct kvs_ent last;

	if (entry_get(&last, ent->kvs, &rdkey) != 0) {
		return 0;
	}

	if ((last.start == ent->start) && (last.val_len != 0U)) {
		return cb->cb(ent, cb->cb_arg);
	}

	return 0;
}

static int entry_walk_unique(const struct kvs *kvs, const struct read_cb *rd,
			     const struct entry_cb *cb, uint32_t bcnt)
{
	const struct entry_cb unique_entry_cb = {
		.cb = unique_walk_cb,
		.cb_arg = (void *)cb,
	};

	return entry_walk(kvs, rd, &unique_entry_cb, bcnt);
}

static int compact_walk_cb(const struct kvs_ent *ent, void *cb_arg)
{
	const struct kvs *kvs = ent->kvs;
	int rc = 0;

	for (int i = 0; i < kvs->cfg->bspr; i++) {
		rc = entry_copy(ent);
		if (rc == 0) {
			break;
		}
		wblock_advance(kvs);
	}

	return rc;
}

static int compact(const struct kvs *kvs, uint32_t bcnt)
{
	const struct kvs_cfg *cfg = kvs->cfg;
	const struct kvs_data *data = kvs->data;
	struct read_cb rdkey;
	struct entry_cb compact_entry_cb;

	rdkey.ctx = NULL;
	compact_entry_cb.cb = compact_walk_cb;
	compact_entry_cb.cb_arg = NULL;

	if (data->pos != (data->bend - cfg->bsz)) {
		wblock_advance(kvs);
	}

	return entry_walk_unique(kvs, &rdkey, &compact_entry_cb, bcnt);
}

int kvs_entry_read(const struct kvs_ent *ent, uint32_t off, void *data,
		   uint32_t len)
{
	if ((ent == NULL) || (ent->kvs == NULL) || (!ent->kvs->data->ready)) {
		return -KVS_EINVAL;
	}

	return entry_read(ent, off, data, len);
}

int kvs_entry_get(struct kvs_ent *ent, const struct kvs *kvs, const char *key)
{
	if ((kvs == NULL) || (!kvs->data->ready) || (key == NULL)) {
		return -KVS_EINVAL;
	}

	return entry_from_key(ent, kvs, key);
}

int kvs_read(const struct kvs *kvs, const char *key, void *value, uint32_t len)
{
	if ((kvs == NULL) || (!kvs->data->ready) || (key == NULL)) {
		return -KVS_EINVAL;
	}

	struct kvs_ent wlk;

	if (kvs_entry_get(&wlk, kvs, key) == 0U) {
		uint32_t off = wlk.val_start;

		return entry_read(&wlk, off, value, len);
	}

	return -KVS_ENOENT;
}

int kvs_write(const struct kvs *kvs, const char *key, const void *value,
	      uint32_t len)
{
	if ((kvs == NULL) || (!kvs->data->ready) || (key == NULL)) {
		return -KVS_EINVAL;
	}

	const struct kvs_cfg *cfg = kvs->cfg;
	struct kvs_ent ent;
	uint32_t cnt = cfg->bcnt - cfg->bspr;
	int rc;

	rc = kvs_dev_lock(kvs);
	if (rc) {
		return rc;
	}

	entry_link(&ent, kvs);
	while (cnt != 0U) {
		rc = entry_add(&ent, key, value, len);
		if (rc == 0) {
			goto end;
		}

		if (kvs->data->gc_disabled) {
			wblock_advance(kvs);
		} else {
			(void)compact(kvs, cfg->bcnt - cnt);
		}
		cnt--;
	}

	rc = -KVS_ENOSPC;
end:
	(void)kvs_dev_unlock(kvs);
	return rc;
}

int kvs_delete(const struct kvs *kvs, const char *key)
{
	return kvs_write(kvs, key, NULL, 0);
}

int kvs_walk_unique(const struct kvs *kvs, const char *key,
		    int (*cb)(const struct kvs_ent *ent, void *cb_arg),
		    void *cb_arg)
{
	if ((kvs == NULL) || (!kvs->data->ready)) {
		return -KVS_EINVAL;
	}

	const struct read_cb rdkey = {
		.ctx = (void *)key,
		.len = KVS_MIN(strlen(key), KVS_KEY_MAXSIZE),
		.off = 0U,
		.read = read_cb_ptr,
	};
	const struct entry_cb entry_cb = {
		.cb = cb,
		.cb_arg = cb_arg,
	};

	return entry_walk_unique(kvs, &rdkey, &entry_cb, kvs->cfg->bcnt);
}

int kvs_walk(const struct kvs *kvs, const char *key,
	     int (*cb)(const struct kvs_ent *ent, void *cb_arg), void *cb_arg)
{
	if ((kvs == NULL) || (!kvs->data->ready)) {
		return -KVS_EINVAL;
	}

	const struct read_cb rdkey = {
		.ctx = (void *)key,
		.len = KVS_MIN(strlen(key), KVS_KEY_MAXSIZE),
		.off = 0U,
		.read = read_cb_ptr,
	};
	const struct entry_cb entry_cb = {
		.cb = cb,
		.cb_arg = cb_arg,
	};

	return entry_walk(kvs, &rdkey, &entry_cb, kvs->cfg->bcnt);
}

int kvs_mount(struct kvs *kvs)
{
	/* basic config checks */
	if ((kvs == NULL) || (kvs->cfg == NULL)) {
		return -KVS_EINVAL;
	}

	/* read/prog routines check */
	if ((kvs->cfg->read == NULL) || (kvs->cfg->prog == NULL)) {
		return -KVS_EINVAL;
	}

	/* program size nonzero and power of 2 */
	if ((kvs->cfg->psz == 0U) ||
	    ((kvs->cfg->psz & (kvs->cfg->psz - 1)) != 0U)) {
		return -KVS_EINVAL;
	}

	/* block size nonzero and power of 2 */
	if ((kvs->cfg->bsz == 0U) ||
	    ((kvs->cfg->bsz & (kvs->cfg->bsz - 1)) != 0U)) {
		return -KVS_EINVAL;
	}

	/* block size larger than program size */
	if (kvs->cfg->bsz < kvs->cfg->psz) {
		return -KVS_EINVAL;
	}

	const struct kvs_cfg *cfg = kvs->cfg;
	struct kvs_data *data = kvs->data;
	struct kvs_ent wlk;
	uint8_t hdr[KVS_HDR_MAXSIZE];
	uint32_t epoch;
	bool last_blck_fnd = false;
	int rc = 0;

	if (data->ready) {
		return -KVS_EAGAIN;
	}

	rc = kvs_dev_init(kvs);
	if (rc != 0) {
		return rc;
	}

	rc = kvs_dev_lock(kvs);
	if (rc != 0) {
		return rc;
	}

	data->pos = 0U;
	data->bend = cfg->bsz;
	data->epoch = 0U;
	entry_link(&wlk, kvs);
	for (int i = 0; i < cfg->bcnt; i++) {
		wlk.start = i * cfg->bsz;
		if (entry_get_info(&wlk) != 0) {
			continue;
		}

		if (entry_read(&wlk, 0, hdr, wlk.key_start - 1) != 0) {
			continue;
		}

		if (ehdr_get_epoch(hdr, &epoch) != 0) {
			continue;
		}

		if (last_blck_fnd && (epoch < data->epoch)) {
			continue;
		}

		data->pos = wlk.start;
		data->bend = wlk.start + cfg->bsz;
		data->epoch = epoch;
		last_blck_fnd = true;
	}

	uint32_t npos = data->pos;

	wlk.next = data->pos;
	wlk.start = wlk.next;
	data->pos = data->bend; /* temporarily set data->pos to the block end */
	while (entry_match_in_block(&wlk, NULL, NULL) == 0) {
		npos = wlk.next;
	}

	data->pos = npos;
	data->ready = true;
	return kvs_dev_unlock(kvs);
}

int kvs_unmount(struct kvs *kvs)
{
	if (kvs == NULL) {
		return -KVS_EINVAL;
	}

	int rc;

	rc = kvs_dev_lock(kvs);
	if (rc != 0) {
		return rc;
	}

	kvs->data->ready = false;
	(void)kvs_dev_unlock(kvs);
	return kvs_dev_release(kvs);
}

int kvs_compact(const struct kvs *kvs)
{
	if ((kvs == NULL) || (!kvs->data->ready))  {
		return -KVS_EINVAL;
	}

	int rc;

	rc = kvs_dev_lock(kvs);
	if (rc != 0) {
		return rc;
	}

	rc = compact(kvs, kvs->cfg->bcnt - kvs->cfg->bspr);
	(void)kvs_dev_unlock(kvs);
	return rc;
}

int kvs_disable_gc(const struct kvs *kvs)
{
	if (kvs == NULL) {
		return -KVS_EINVAL;
	}

	int rc;

	rc = kvs_dev_lock(kvs);
	if (rc != 0) {
		return rc;
	}

	kvs->data->gc_disabled = true;
	(void)kvs_dev_unlock(kvs);
	return rc;
}

int kvs_enable_gc(const struct kvs *kvs)
{
	if (kvs == NULL) {
		return -KVS_EINVAL;
	}

	int rc;

	rc = kvs_dev_lock(kvs);
	if (rc != 0) {
		return rc;
	}

	kvs->data->gc_disabled = false;
	(void)kvs_dev_unlock(kvs);
	return rc;
}