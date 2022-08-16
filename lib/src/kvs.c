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

	return cfg->sync(cfg->ctx);
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

static uint32_t ehdr_ebc(const uint8_t *hdr)
{
	return (((*hdr) & 0b00110000) >> 4);
}

static uint32_t ehdr_kbc(const uint8_t *hdr)
{
	return 1U + (((*hdr) & 0b00001100) >> 2);
}

static uint32_t ehdr_vbc(const uint8_t *hdr)
{
	return 1U + ((*hdr) & 0b00000011);
}

static uint32_t ehdr_len(const uint8_t *hdr)
{
	return 1U + ehdr_ebc(hdr) + ehdr_kbc(hdr) + ehdr_vbc(hdr);
}

static int read_ehdr(const uint8_t *hdr, uint32_t *elen, uint32_t *klen,
		     uint32_t *vlen)
{
	uint8_t *s = (uint8_t *)hdr;

	*elen = 0U;
	*klen = 0U;
	*vlen = 0U;

	if (((*s++) & KVS_HDRSTART_MASK) != KVS_HDRSTART) {
		return -KVS_ENOENT;
	}

	for (uint32_t i = 0; i < ehdr_ebc(hdr); i++) {
		*elen += ((*s++) << (8 * i));
	}

	for (uint32_t i = 0; i < ehdr_kbc(hdr); i++) {
		*klen += ((*s++) << (8 * i));
	}

	for (uint32_t i = 0; i < ehdr_vbc(hdr); i++) {
		*vlen += ((*s++) << (8 * i));
	}

	return 0;
}

static void make_ehdr(uint8_t *hdr, uint32_t elen, uint32_t klen, uint32_t vlen)
{
	uint8_t *s = hdr;

	(*s++) = KVS_HDRSTART;

	while (elen != 0U) {
		*s++ = (uint8_t)(elen & 0xff);
		elen >>= 8;
		(*hdr) += 16;
	}

	while (true) {
		*s++ = (uint8_t)(klen & 0xff);
		klen >>= 8;
		if (klen == 0U) {
			break;
		}

		(*hdr) += 4;
	}

	while (true) {
		*s++ = (uint8_t)(vlen & 0xff);
		vlen >>= 8;
		if (vlen == 0U) {
			break;
		}

		(*hdr) += 1;
	}
}

static int entry_read(const struct kvs_ent *ent, uint32_t off, void *data,
		      uint32_t len)
{
	const struct kvs *kvs = ent->kvs;

	len = KVS_MIN(len, ent->next - (ent->start + off));
	return kvs_dev_read(kvs, ent->start + off, data, len);
}

static int entry_write(const struct kvs_ent *ent, uint32_t off, const void *data,
		       uint32_t len)
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
		const uint32_t rdlen = KVS_MIN(len, rem);
		uint8_t *buf = pbuf8 + (psz - rem);

		memcpy(buf, data8, rdlen);
		if (rdlen == rem) {
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

		data8 += rdlen;
		len -= rdlen;
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

struct key_read_cb {
	const void *ctx;
	uint32_t len;
	int (*read)(const void *ctx, uint32_t off, void *data, uint32_t len);
};

static int key_read_cb_entry(const void *ctx, uint32_t off, void *data,
			     uint32_t len)
{
	struct kvs_ent *ent = (struct kvs_ent *)(ctx);

	return entry_read(ent, ent->key_start + off, data, len);
}

static int key_read_cb_const(const void *ctx, uint32_t off, void *data,
			     uint32_t len)
{
	uint8_t *src = (uint8_t *)ctx;

	memcpy(data, src + off, len);
	return 0;
}

static bool key_starts_with(const struct kvs_ent *ent,
			    const struct key_read_cb *rd)
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

		rc = rd->read(rd->ctx, off, bufr, rdlen);
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

struct block_start_ext {
	uint32_t magic;
	uint32_t epoch;
};

static void entry_link(struct kvs_ent *ent, const struct kvs *kvs)
{
	ent->kvs = (struct kvs *)kvs;
}

static int entry_write_hdr(struct kvs_ent *ent)
{
	const struct kvs *kvs = ent->kvs;
	const uint32_t key_len = ent->val_start;
	const uint32_t val_len = ent->val_len;
	const uint32_t psz = kvs->cfg->psz;
	const uint32_t bsz = kvs->cfg->bsz;
	const struct block_start_ext ext = {
		.magic = KVS_MAGIC,
		.epoch = kvs->data->epoch,
	};
	struct kvs_data *data = kvs->data;
	uint8_t hdr[KVS_MAXHDRSIZE];
	uint32_t ext_len, hdr_len, len;
	int rc;

	if (data->pos == KVS_ALIGNDOWN(data->pos, bsz)) {
		ext_len = sizeof(struct block_start_ext);
	} else {
		ext_len = 0U;
	}

	make_ehdr(hdr, ext_len, key_len, val_len);
	hdr_len = ehdr_len(hdr);
	ent->ext_start = hdr_len;
	ent->key_start = ent->ext_start + ext_len;
	ent->val_start = ent->key_start + key_len;
	ent->val_len = val_len;
	len = KVS_ALIGNDOWN(ent->val_start + ent->val_len, psz) + psz;

	if ((data->pos + len) > data->bend) {
		return -KVS_ENOSPC;
	}

	ent->start = data->pos;
	ent->next = ent->start + len;
	data->pos = ent->next;

	rc = entry_write(ent, 0, hdr, hdr_len);
	if (rc != 0) {
		goto end;
	}

	rc = entry_write(ent, ent->ext_start, &ext, ext_len);
end:
	return rc;
}

static int entry_write_trl(struct kvs_ent *ent)
{
	const struct kvs *kvs = ent->kvs;
	const uint8_t fill = KVS_FILLCHAR;
	uint32_t off = ent->val_start + ent->val_len;
	uint32_t len = ent->next - ent->start - off;
	int rc;

	while (len != 0U) {
		rc = entry_write(ent, off, &fill, 1);
		if (rc != 0) {
			goto end;
		}

		len--;
		off++;
	}

	rc = kvs_dev_sync(kvs);
end:
	return rc;
}

static int entry_add(struct kvs_ent *ent, const char *key, const void *value,
		     uint32_t len)
{
	int rc;

	ent->ext_start = 0;
	ent->key_start = 0;
	ent->val_start = strlen(key);
	ent->val_len = len;

	rc = entry_write_hdr(ent);
	if (rc != 0) {
		goto end;
	}

	rc = entry_write(ent, ent->key_start, key, strlen(key));
	if (rc != 0) {
		goto end;
	}

	rc = entry_write(ent, ent->val_start, value, len);
	if (rc != 0) {
		goto end;
	}

	return entry_write_trl(ent);
end:
	return rc;
}

static int entry_copy(const struct kvs_ent *ent)
{
	const uint32_t key_len = ent->val_start - ent->key_start;
	char key[key_len + 1];
	uint8_t value[ent->val_len];
	struct kvs_ent cp_ent;

	if (entry_read(ent, ent->key_start, key, key_len) != 0) {
		/* loosing a bad entry */
		return 0;
	}

	if (entry_read(ent, ent->val_start, value, sizeof(value)) != 0) {
		/* loosing a bad entry */
		return 0;
	}

	key[key_len] = '\0';
	entry_link(&cp_ent, ent->kvs);
	return entry_add(&cp_ent, key, value, sizeof(value));
}

// static int entry_copy(const struct kvs_ent *ent)
// {
// 	struct kvs_ent cp_ent = {
// 		.kvs = (struct kvs *)ent->kvs,
// 		.val_start = ent->val_start - ent->key_start,
// 		.val_len = ent->val_len,
// 	};
// 	uint8_t buf[KVS_BUFSIZE];
// 	uint32_t len, off;
// 	int rc;

// 	rc = entry_write_hdr(&cp_ent);
// 	if (rc != 0) {
// 		goto end;
// 	}

// 	len = cp_ent.val_start - cp_ent.key_start + cp_ent.val_len;
// 	off = 0U;
// 	while (len != 0U) {
// 		const uint32_t rdlen = KVS_MIN(len, sizeof(buf));

// 		rc = entry_read(ent, ent->key_start + off, buf, rdlen);
// 		if (rc != 0) {
// 			goto end;
// 		}

// 		rc = entry_write(&cp_ent, cp_ent.key_start + off, buf, rdlen);
// 		if (rc != 0) {
// 			goto end;
// 		}
// 		len -= rdlen;
// 		off += rdlen;
// 	}

// 	return entry_write_trl(&cp_ent);
// end:
// 	return rc;
// }

static int entry_get_info(struct kvs_ent *ent)
{
	const struct kvs *kvs = ent->kvs;
	const struct kvs_cfg *cfg = kvs->cfg;
	const uint32_t psz = cfg->psz;
	uint8_t hdr[KVS_MAXHDRSIZE], fill;
	uint32_t hdr_len, ext_len, key_len, val_len;
	int rc;

	ent->next = KVS_ALIGNDOWN(ent->start, cfg->bsz) + cfg->bsz;
	rc = entry_read(ent, 0, hdr, sizeof(hdr));
	if (rc != 0) {
		goto end;
	}

	rc = read_ehdr(hdr, &ext_len, &key_len, &val_len);
	if (rc != 0) {
		goto end;
	}

	hdr_len = ehdr_len(hdr);

	rc = entry_read(ent, hdr_len + ext_len + key_len + val_len, &fill, 1);
	if ((rc != 0) || (fill != KVS_FILLCHAR)) {
		goto end;
	}

	ent->ext_start = hdr_len;
	ent->key_start = ent->ext_start + ext_len;
	ent->val_start = ent->key_start + key_len;
	ent->val_len = val_len;
	ent->next = ent->start +
		    KVS_ALIGNDOWN(ent->val_start + ent->val_len, psz) + psz;
	return 0;
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
	const uint32_t bend = KVS_ALIGNDOWN(ent->start, bsz) + bsz;

	while (ent->next < bend) {
		ent->start = ent->next;
		if (entry_get_info(ent) != 0) {
			break;
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
			     bool (*match)(const struct kvs_ent *ent, void *arg),
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
	struct key_read_cb *arg = (struct key_read_cb *)cb_arg;

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
	struct key_read_cb *arg = (struct key_read_cb *)cb_arg;

	if ((ent->val_start - ent->key_start) != arg->len) {
		return false;
	}

	return match_key_start(ent, cb_arg);
}

static int entry_get(struct kvs_ent *ent, const struct kvs *kvs,
		     struct key_read_cb *rdkey)
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
	struct key_read_cb rdkey = {
		.len = strlen(key),
		.ctx = (void *)key,
		.read = key_read_cb_const,
	};

	return entry_get(ent, kvs, &rdkey);
}

struct entry_cb {
	void *cb_arg;
	int (*cb)(const struct kvs_ent *entry, void *cb_arg);
};

static int entry_walk_unique(const struct kvs *kvs, struct key_read_cb *rd,
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
		while (entry_match_in_block(&wlk, match_key_start, (void *)rd) ==
		       0) {
			struct key_read_cb rdwlkkey;
			struct kvs_ent last;

			rdwlkkey.len = wlk.val_start - wlk.key_start;
			rdwlkkey.ctx = (void *)&wlk;
			rdwlkkey.read = key_read_cb_entry;

			if (entry_get(&last, kvs, &rdwlkkey) != 0) {
				continue;
			}

			if ((last.start == wlk.start) && (last.val_len != 0U)) {
				rc = cb->cb(&wlk, cb->cb_arg);
				if (rc != 0) {
					goto end;
				}
			}
		}
		wlk.next = (wlk.next < end) ? wlk.next : 0U;
	}
end:
	return rc;
}

static int entry_walk(const struct kvs *kvs, struct key_read_cb *rd,
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
		while (entry_match_in_block(&wlk, NULL, NULL) == 0) {
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
	struct key_read_cb rdkey;
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
		(void)compact(kvs, cfg->bcnt - cnt);
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

	struct key_read_cb rdkey = {
		.ctx = (void *)key,
		.len = strlen(key),
		.read = key_read_cb_const,
	};
	struct entry_cb entry_cb = {
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

	struct key_read_cb rdkey = {
		.ctx = (void *)key,
		.len = strlen(key),
		.read = key_read_cb_const,
	};
	struct entry_cb entry_cb = {
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
		if (entry_get_info(&wlk) == 0) {
			struct block_start_ext extra;
			uint32_t rdlen = sizeof(struct block_start_ext);

			rc = entry_read(&wlk, wlk.ext_start, &extra, rdlen);
			if ((wlk.key_start - wlk.ext_start) != rdlen) {
				rc = -KVS_EDEADLK;
			}

			if (rc != 0) {
				goto end;
			}

			if ((extra.epoch >= data->epoch) || (!last_blck_fnd)) {
				data->pos = wlk.start;
				data->bend = wlk.start + cfg->bsz;
				data->epoch = extra.epoch;
				last_blck_fnd = true;
			}
		}
	}

	wlk.next = data->pos;
	wlk.start = wlk.next;
	while (entry_match_in_block(&wlk, NULL, NULL) == 0) {
		data->pos = wlk.next;
	}

	data->ready = true;

end:
	(void)kvs_dev_unlock(kvs);
	return rc;
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
	if (kvs == NULL) {
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