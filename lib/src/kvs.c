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

static uint32_t kvs_get_le32(const uint8_t *buf)
{
	return (uint32_t)buf[0] + ((uint32_t)buf[1] << 8) +
	       ((uint32_t)buf[2] << 16) + ((uint32_t)buf[3] << 24);
}

static void kvs_put_le32(uint8_t *buf, uint32_t value)
{
	buf[0] = (uint8_t)(value & 0x000000ff);
	buf[1] = (uint8_t)((value & 0x0000ff00) >> 8);
	buf[2] = (uint8_t)((value & 0x00ff0000) >> 16);
	buf[3] = (uint8_t)((value & 0xff000000) >> 24);
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

static int entry_read(const struct kvs_ent *ent, uint32_t off, void *data,
		      uint32_t len)
{
	const struct kvs *kvs = ent->kvs;

	len = KVS_MIN(len, ent->next - (ent->start + off));
	return kvs_dev_read(kvs, ent->start + off, data, len);
}

static int entry_write_nocrc(const struct kvs_ent *ent, uint32_t off,
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

static int entry_write(struct kvs_ent *ent, uint32_t off, const void *data,
		       uint32_t len)
{
	ent->crc32 = kvs_crc32(ent->crc32, data, len);
	return entry_write_nocrc(ent, off, data, len);
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

/* get lengths from entry header */
static void ehdr_get_lengths(const uint8_t *hdr, uint32_t *lengths)
{
	uint32_t hdr_off = 1U;

	for (uint32_t i = 0U; i < 2U; i++) {

		uint32_t bc = 1U + ((hdr[0] >> (2 - 2 * i)) & 0x3);
		uint32_t len = 0U;

		for (uint32_t j = 0U; j < bc; j++) {
			len += ((uint32_t)(hdr[hdr_off++]) << (8 * j));
		}

		lengths[i] = len;
	}

}

/* set lengths in entry header */
static void ehdr_set_lengths(const uint32_t *lengths, uint8_t *hdr)
{
	uint32_t hdr_off = 1U;

	hdr[0] = 0;
	for (uint32_t i = 0U; i < 2U; i++) {
		uint32_t len = lengths[i];
		while (true) {
			hdr[hdr_off++] = (uint8_t)(len & 0xff);
			len >>= 8;
			if (len == 0U) {
				break;
			}
			hdr[0] += 1 << (2 - 2 * i);
		}

	}

}

/* start position of wrap count from entry header */
static uint32_t ehdr_wrapcntpos(const uint8_t *hdr)
{
	return 3U + (hdr[0] & 0x3) + ((hdr[0] >> 2) & 0x3);
}

/* start position of first data block (key) from entry header */
static uint32_t ehdr_datapos(const uint8_t *hdr)
{
	uint32_t rv = ehdr_wrapcntpos(hdr);

	if ((hdr[0] & KVS_WRAPCNT_BITMASK) != KVS_WRAPCNT_BITMASK) {
		return rv;
	}

	return rv + KVS_WRAPCNTSIZE;
}

/* get wrap counter from entry header */
static int ehdr_get_wrapcnt(const uint8_t *hdr, uint32_t *wrapcnt)
{
	if ((hdr[0] & KVS_WRAPCNT_BITMASK) != KVS_WRAPCNT_BITMASK) {
		return -KVS_ENOENT;
	}

	*wrapcnt = kvs_get_le32(&hdr[ehdr_wrapcntpos(hdr)]);
	return 0;
}

/* set wrap counter in entry header */
static void ehdr_set_wrapcnt(uint8_t *hdr, uint32_t wrapcnt)
{
	hdr[0] |= KVS_WRAPCNT_BITMASK;
	hdr += ehdr_wrapcntpos(hdr);
	kvs_put_le32(hdr, wrapcnt);
}

static int entry_crc32_calculate(const struct kvs_ent *ent, uint32_t *crc32,
				 uint32_t len)
{
	uint32_t off = 0U;
	uint8_t buf[KVS_BUFSIZE];
	int rc = 0;

	while (len != 0) {
		uint32_t rdlen = KVS_MIN(len, sizeof(buf));
		rc = entry_read(ent, off, buf, rdlen);
		if (rc != 0U) {
			goto end;
		}
		*crc32 = kvs_crc32(*crc32, buf, rdlen);
		off += rdlen;
		len -= rdlen;
	}

end:
	return rc;
}

static bool entry_crc32_ok(const struct kvs_ent *ent, uint32_t dlen,
			   uint32_t tlen)
{
	uint8_t buf[KVS_CRCSIZE];
	uint32_t crc32 = 0U;

	if (entry_crc32_calculate(ent, &crc32, dlen) != 0) {
		return false;
	}

	if (entry_read(ent, tlen - KVS_CRCSIZE, buf, sizeof(buf)) != 0) {
		return false;
	}

	if (crc32 != kvs_get_le32(buf)) {
		return false;
	}

	return true;
}

static int entry_get_info(struct kvs_ent *ent, uint32_t *wrapcnt)
{
	const uint32_t bsz = ent->kvs->cfg->bsz;
	const uint32_t psz = ent->kvs->cfg->psz;
	uint32_t lengths[2], dlen, tlen;
	uint8_t hdr[KVS_HDR_BUFSIZE];

	ent->next = KVS_ALIGNDOWN(ent->start, bsz) + bsz;
	if (entry_read(ent, 0, hdr, sizeof(hdr)) != 0) {
		goto end;
	}

	if (!ehdr_has_odd_parity(hdr)) {
		goto end;
	}

	ehdr_get_lengths(hdr, lengths);
	dlen = ehdr_datapos(hdr) + lengths[0] + lengths[1];
	tlen = KVS_ALIGNUP(dlen + KVS_CRCSIZE, psz);

	if ((ent->next - ent->start) < tlen) {
		goto end;
	}

	if (!entry_crc32_ok(ent, dlen, tlen)) {
		goto end;
	}

	if (ehdr_get_wrapcnt(hdr, wrapcnt) != 0)
	{
		wrapcnt = NULL;
	}

	ent->key_start = ehdr_datapos(hdr);
	ent->val_start = ent->key_start + lengths[0];
	ent->fil_start = ent->val_start + lengths[1];
	ent->next = ent->start + tlen;
	return 0;
end:
	return -KVS_ENOENT;
}

static int entry_set_info(struct kvs_ent *ent, uint8_t *hdr, uint32_t klen,
			  uint32_t vlen)
{
	const uint32_t bsz = ent->kvs->cfg->bsz;
	const uint32_t psz = ent->kvs->cfg->psz;
	struct kvs_data *data = ent->kvs->data;
	uint32_t lengths[2], dlen, tlen;

	lengths[0] = klen;
	lengths[1] = vlen;
	ehdr_set_lengths(lengths, hdr);
	if (data->pos == KVS_ALIGNDOWN(data->pos, bsz)) {
		ehdr_set_wrapcnt(hdr, data->wrapcnt);
	}

	dlen = ehdr_datapos(hdr) + klen + vlen;
	tlen = KVS_ALIGNUP(dlen + KVS_CRCSIZE, psz);
	if ((data->bend - data->pos) < tlen) {
		return -KVS_ENOSPC;
	}

	ehdr_set_odd_parity(hdr);
	ent->start = data->pos;
	ent->next = data->pos + tlen;
	ent->key_start = ehdr_datapos(hdr);
	ent->val_start = ent->key_start + klen;
	ent->fil_start = ent->val_start + vlen;
	ent->crc32 = 0U;
	data->pos = ent->next;
	return 0;
}

static void wblock_advance(const struct kvs *kvs)
{
	const struct kvs_cfg *cfg = kvs->cfg;
	struct kvs_data *data = kvs->data;

	data->pos = data->bend;
	if (data->pos == (cfg->bcnt * cfg->bsz)) {
		data->wrapcnt++;
		data->pos = 0U;
	}

	data->bend = data->pos + cfg->bsz;
}

static void entry_link(struct kvs_ent *ent, const struct kvs *kvs)
{
	ent->kvs = (struct kvs *)kvs;
}

static int entry_write_hdr(struct kvs_ent *ent, uint32_t key_len,
			   uint32_t val_len)
{
	uint32_t len;
	uint8_t hdr[KVS_HDR_BUFSIZE];
	int rc;

	rc = entry_set_info(ent, hdr, key_len, val_len);
	if (rc != 0) {
		return rc;
	}

	len = ehdr_datapos(hdr);
	return entry_write(ent, 0, hdr, len);
}

static int entry_write_crc(struct kvs_ent *ent)
{
	const uint32_t tlen = ent->next - ent->start - KVS_CRCSIZE;
	const uint8_t fill = KVS_FILLCHAR;
	uint8_t buf[KVS_CRCSIZE];
	uint32_t off = ent->fil_start;
	int rc;

	while (off < tlen) {
		rc = entry_write_nocrc(ent, off, &fill, 1);
		if (rc) {
			return rc;
		}

		off++;
	}

	kvs_put_le32(buf, ent->crc32);
	return entry_write_nocrc(ent, off, buf, KVS_CRCSIZE);
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
		.len = strlen(key),
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
		.len = ent->fil_start - ent->val_start,
		.read = read_cb_entry,
	};
	struct kvs_ent cp_ent;

	entry_link(&cp_ent, ent->kvs);
	return entry_append(&cp_ent, &krd_cb, &vrd_cb);
}

static bool differ(const struct read_cb *rda, const struct read_cb *rdb)
{
	if (rda->len != rdb->len) {
		return true;
	}

	uint32_t len = rda->len;
	uint32_t off = 0U;

	while (len != 0U) {
		uint8_t bufa[KVS_BUFSIZE], bufb[KVS_BUFSIZE];
		uint32_t rdlen = KVS_MIN(len, KVS_BUFSIZE);

		if (rda->read(rda->ctx, rda->off + off, bufa, rdlen) != 0) {
			return true;
		};

		if (rdb->read(rdb->ctx, rdb->off + off, bufb, rdlen) != 0) {
			return true;
		};

		if (memcmp(bufa, bufb, rdlen) != 0) {
			return true;
		}

		len -= rdlen;
		off += rdlen;
	}

	return false;
}

struct entry_cb {
	int (*cb)(const struct kvs_ent *entry, void *cb_arg);
	void *cb_arg;
};

static int walk_in_block(struct kvs_ent *ent, const struct read_cb *rdkey,
			 const struct entry_cb *cb)
{
	const struct kvs *kvs = ent->kvs;
	const uint32_t bsz = kvs->cfg->bsz;
	const uint32_t psz = kvs->cfg->psz;
	uint32_t bend = KVS_ALIGNDOWN(ent->next, bsz) + bsz;
	uint32_t wrapcnt;
	uint32_t *wrapcntptr = &wrapcnt;
	int rc = 0;

	if (bend == kvs->data->bend) {
		bend = kvs->data->pos;
	}

	while (ent->next < bend) {
		ent->start = ent->next;
		if (entry_get_info(ent, wrapcntptr) != 0) {
			ent->next = ent->start + psz;
			continue;
		}

		/* avoid reading info from bad blocks */
		if ((wrapcntptr != NULL) &&
		    ((wrapcnt + 1U) < kvs->data->wrapcnt)) {
			ent->next = bend;
			continue;
		}

		const struct read_cb readkey = {
			.ctx = (void *)ent,
			.off = ent->key_start,
			.len = rdkey->len,
			.read = read_cb_entry,
		};

		if (differ(&readkey, rdkey)) {
			continue;
		}

		rc = cb->cb(ent, cb->cb_arg);
		if (rc) {
			goto end;
		}
	}

end:
	return rc;
}

static int walk(const struct kvs *kvs, const struct read_cb *rdkey,
		const struct entry_cb *cb, uint32_t bcnt)
{
	const uint32_t bsz = kvs->cfg->bsz;
	const uint32_t end = kvs->cfg->bcnt * bsz;
	const uint32_t bend = kvs->data->bend;
	struct kvs_ent wlk;
	int rc = 0;

	entry_link(&wlk, kvs);
	wlk.next = (bend < end) ? bend : 0U;
	for (int i = 0; i < bcnt; i++) {
		wlk.start = wlk.next;
		rc = walk_in_block(&wlk, rdkey, cb);
		if (rc) {
			goto end;
		}

		wlk.next = KVS_ALIGNDOWN(wlk.start, bsz) + bsz;
		wlk.next = (wlk.next < end) ? wlk.next : 0U;
	}
end:
	return rc;
}

struct entry_get_cb_arg {
	struct kvs_ent *ent;
	uint32_t klen;
	bool found;
};

static int entry_get_cb(const struct kvs_ent *ent, void *cb_arg)
{
	struct entry_get_cb_arg *rv = (struct entry_get_cb_arg *)cb_arg;

	if ((ent->val_start - ent->key_start) == rv->klen) {
		memcpy(rv->ent, ent, sizeof(struct kvs_ent));
		rv->found = true;
	}

	return 0;
}

static int entry_get(struct kvs_ent *ent, const struct kvs *kvs,
		     const struct read_cb *rdkey)
{
	const uint32_t bsz = kvs->cfg->bsz;
	const uint32_t bcnt = kvs->cfg->bcnt;
	const uint32_t end = bcnt * bsz;
	struct kvs_ent wlk;
	struct entry_get_cb_arg cb_arg = {
		.ent = ent,
		.klen = rdkey->len,
		.found = false,
	};
	struct entry_cb cb = {
		.cb = entry_get_cb,
		.cb_arg = (void *)&cb_arg,
	};

	entry_link(ent, kvs);
	entry_link(&wlk, kvs);
	wlk.next = KVS_ALIGNDOWN(kvs->data->pos, bsz);
	for (int i = 0; i < bcnt; i++) {
		wlk.start = wlk.next;
		if (walk_in_block(&wlk, rdkey, &cb)) {
			goto end;
		}

		if (cb_arg.found) {
			break;
		}

		wlk.next = KVS_ALIGNDOWN(wlk.start, bsz);
		wlk.next = (wlk.next == 0U) ? end : wlk.next;
		wlk.next -= bsz;
	}

	return 0;
end:
	return -KVS_ENOENT;
}

static int unique_cb(const struct kvs_ent *ent, void *cb_arg)
{
	const struct kvs *kvs = ent->kvs;
	const struct entry_cb *cb = (const struct entry_cb *)cb_arg;
	const struct read_cb readkey = {
		.ctx = (void *)ent,
		.off = ent->key_start,
		.len = ent->val_start - ent->key_start,
		.read = read_cb_entry,
	};
	struct kvs_ent wlk;

	(void)entry_get(&wlk, kvs, &readkey);
	if ((ent->start == wlk.start) && (ent->fil_start != ent->val_start)) {
		return cb->cb(ent, cb->cb_arg);
	}

	return 0;
}

static int walk_unique(const struct kvs *kvs, const struct read_cb *rdkey,
		       const struct entry_cb *cb, uint32_t bcnt)
{
	const struct entry_cb walk_cb = {
		.cb = unique_cb,
		.cb_arg = (void *)cb,
	};

	return walk(kvs, rdkey, &walk_cb, bcnt);
}

int copy_cb(const struct kvs_ent *ent, void *cb_arg)
{
	int rc = 0;

	for (int i = 0; i < ent->kvs->cfg->bspr; i++) {
	 	rc = entry_copy(ent);
	 	if (rc == 0) {
	 		break;
	 	}
	 	wblock_advance(ent->kvs);
	}

	return rc;
}

static int compact(const struct kvs *kvs, uint32_t bcnt)
{
	const struct kvs_cfg *cfg = kvs->cfg;
	const struct kvs_data *data = kvs->data;
	const struct read_cb rdkey = {
		.ctx = (void *)NULL,
		.off = 0U,
		.len = 0U,
		.read = read_cb_ptr,
	};
	const struct entry_cb compact_cb = {
		.cb = copy_cb,
	};

	if (data->pos != (data->bend - cfg->bsz)) {
		wblock_advance(kvs);
	}

	return walk_unique(kvs, &rdkey, &compact_cb, bcnt);
}

int kvs_entry_read(const struct kvs_ent *ent, uint32_t off, void *data,
		   uint32_t len)
{
	if ((ent == NULL) || (ent->kvs == NULL) || (!ent->kvs->data->ready)) {
		return -KVS_EINVAL;
	}

	const uint32_t psz = ent->kvs->cfg->psz;
	const uint32_t dlen = ent->fil_start;
	const uint32_t tlen = KVS_ALIGNUP(dlen + KVS_CRCSIZE, psz);

	if (!entry_crc32_ok(ent, dlen, tlen)) {
		return -KVS_ENOENT;
	}

	return entry_read(ent, off, data, len);
}

int kvs_entry_get(struct kvs_ent *ent, const struct kvs *kvs, const char *key)
{
	if ((kvs == NULL) || (!kvs->data->ready) || (key == NULL)) {
		return -KVS_EINVAL;
	}

	const struct read_cb krd_cb = {
		.ctx = (void *)key,
		.off = 0U,
		.len = strlen(key),
		.read = read_cb_ptr,
	};

	return entry_get(ent, kvs, &krd_cb);
}

int kvs_read(const struct kvs *kvs, const char *key, void *value, uint32_t len)
{
	struct kvs_ent wlk;
	int rc;

	rc = kvs_entry_get(&wlk, kvs, key);
	if (rc != 0) {
		return rc;
	}

	if (wlk.fil_start == wlk.val_start) {
		return -KVS_ENOENT;
	}

	return entry_read(&wlk, wlk.val_start, value, len);
}

int kvs_write(const struct kvs *kvs, const char *key, const void *value,
	      uint32_t len)
{
	if ((kvs == NULL) || (!kvs->data->ready) || (key == NULL)) {
		return -KVS_EINVAL;
	}

	struct kvs_ent ent;

	if (kvs_entry_get(&ent, kvs, key) == 0) {
		const struct read_cb val_rd = {
			.ctx = (void *)value,
			.len = len,
			.off = 0U,
			.read = read_cb_ptr,
		};
		const struct read_cb entval_rd = {
			.ctx = (void *)&ent,
			.off = ent.val_start,
			.len = ent.fil_start - ent.val_start,
			.read = read_cb_entry,
		};

		if (!differ(&val_rd, &entval_rd)) {
		 	return 0;
		}

	};

	const uint32_t bcnt = kvs->cfg->bcnt;
	uint32_t cnt = bcnt - kvs->cfg->bspr;
	int rc;

	rc = kvs_dev_lock(kvs);
	if (rc) {
		return rc;
	}

	while (cnt != 0U) {
		rc = entry_add(&ent, key, value, len);
		if (rc == 0) {
			goto end;
		}

		rc = compact(kvs, bcnt - cnt);
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
		.len = strlen(key),
		.off = 0U,
		.read = read_cb_ptr,
	};
	const struct entry_cb unique_cb = {
		.cb = cb,
		.cb_arg = cb_arg,
	};

	return walk_unique(kvs, &rdkey, &unique_cb, kvs->cfg->bcnt);
}

int kvs_walk(const struct kvs *kvs, const char *key,
	     int (*cb)(const struct kvs_ent *ent, void *cb_arg), void *cb_arg)
{
	if ((kvs == NULL) || (!kvs->data->ready)) {
		return -KVS_EINVAL;
	}

	const struct read_cb rdkey = {
		.ctx = (void *)key,
		.len = strlen(key),
		.off = 0U,
		.read = read_cb_ptr,
	};
	const struct entry_cb entry_cb = {
		.cb = cb,
		.cb_arg = cb_arg,
	};

	return walk(kvs, &rdkey, &entry_cb, kvs->cfg->bcnt);
}

int kvs_mount(struct kvs *kvs)
{
	int rc;

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

	if (kvs->data->ready) {
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

	const uint32_t bcnt = kvs->cfg->bcnt;
	const uint32_t bsz = kvs->cfg->bsz;
	uint32_t wrapcnt;
	uint32_t *wrapcntptr = &wrapcnt;
	struct kvs_data *data = kvs->data;
	struct kvs_ent wlk;
	bool last_blck_fnd = false;

	data->pos = 0U;
	data->bend = bsz;
	data->wrapcnt = 0U;
	entry_link(&wlk, kvs);
	for (int i = 0; i < bcnt; i++) {
		wlk.start = i * bsz;
		if (entry_get_info(&wlk, wrapcntptr) != 0) {
			continue;
		}

		if (last_blck_fnd && (wrapcnt < data->wrapcnt)) {
			continue;
		}

		data->pos = wlk.next;
		data->bend = wlk.start + bsz;
		data->wrapcnt = wrapcnt;
		last_blck_fnd = true;
	}

	uint32_t npos = data->pos;
	wlk.next = npos;
	data->pos = data->bend;
	while (wlk.next < data->bend) {
		wlk.start = wlk.next;
		if (entry_get_info(&wlk, wrapcntptr) == 0) {
			npos = wlk.next;
		} else {
			wlk.next = wlk.start + kvs->cfg->psz;
		}
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

int kvs_erase(struct kvs *kvs)
{
	uint8_t fillchar = KVS_FILLCHAR;
	uint32_t off = 0U;
	int rc;

	if (kvs == NULL) {
		return -KVS_EINVAL;
	}

	if (kvs->data->ready) {
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

	while (off < (kvs->cfg->bsz * kvs->cfg->bcnt)) {
		(void)kvs_dev_prog(kvs, off, &fillchar, 1);
		off++;
	}

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