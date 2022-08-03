/*
 * Key Value Store
 *
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "kvs/kvs.h"
#include <sys/printk.h>

#include <string.h>

static uint32_t entry_hdr_elen(const uint8_t *hdr)
{
	return (((*hdr) & 0b00110000) >> 4);
}
static uint32_t entry_hdr_klen(const uint8_t *hdr)
{
	return 1U + (((*hdr) & 0b00001100) >> 2);
}

static uint32_t entry_hdr_vlen(const uint8_t *hdr)
{
	return 1U + ((*hdr) & 0b00000011);
}

static uint32_t entry_hdr_len(const uint8_t *hdr)
{
	return 1U + entry_hdr_elen(hdr) + entry_hdr_klen(hdr) + entry_hdr_vlen(hdr);
}

static void make_entry_hdr(uint8_t *hdr, uint32_t elen, uint32_t klen, uint32_t vlen)
{
	uint8_t *s = hdr;

	(*s++) = KVS_HDRSTART;

	while (elen != 0U) {
		*s++ = (uint8_t)(elen & 0xff);
		elen >>= 8;
		(*hdr) += 16;
	}

	while (1) {
		*s++ = (uint8_t)(klen & 0xff);
		klen >>= 8;
		if (klen == 0U) {
			break;
		}

		(*hdr) += 4;
	}

	while (1) {
		*s++ = (uint8_t)(vlen & 0xff);
		vlen >>= 8;
		if (vlen == 0U) {
			break;
		}

		(*hdr) += 1;
	}
}

static int read_entry_hdr(const uint8_t *hdr, uint32_t *elen, uint32_t *klen, uint32_t *vlen)
{
	uint8_t *s = (uint8_t *)hdr;

	*elen = 0U;
	*klen = 0U;
	*vlen = 0U;

	if (((*s++) & KVS_HDRSTART_MASK) != KVS_HDRSTART) {
		return -KVS_ENOENT;
	}

	for (uint32_t i = 0; i < entry_hdr_elen(hdr); i++) {
		*elen += ((*s++) << (8 * i));
	}

	for (uint32_t i = 0; i < entry_hdr_klen(hdr); i++) {
		*klen += ((*s++) << (8 * i));
	}

	for (uint32_t i = 0; i < entry_hdr_vlen(hdr); i++) {
		*vlen += ((*s++) << (8 * i));
	}

	return 0;
}

static int entry_read(const struct kvs_ent *ent, uint32_t off, void *data, uint32_t len)
{
	const struct kvs *kvs = KVS_CONTAINER_OF(ent->kvs_id, struct kvs, id);
	const struct kvs_cfg *cfg = kvs->cfg;
	const uint32_t bsize = cfg->bsize;
	const uint32_t bend = KVS_ALIGNDOWN(ent->start, bsize) + bsize;
	
	len = KVS_MIN(len, bend - (ent->start + off));
	return cfg->read(cfg->ctx, ent->start + off, data, len);
}

static int entry_write(const struct kvs_ent *ent, uint32_t off, const void *data, uint32_t len)
{
	const struct kvs *kvs = KVS_CONTAINER_OF(ent->kvs_id, struct kvs, id);
	const struct kvs_cfg *cfg = kvs->cfg;
	const uint32_t psize = cfg->psize;
	const uint32_t rem = KVS_ALIGNUP(off, psize) - off;
	uint8_t *pbuf8 = (uint8_t *)cfg->pbuf;
	uint8_t *data8 = (uint8_t *)data;
	int rc = 0;

	if ((kvs->data->wr_ent != ent) || ((ent->next - ent->start) < (off + len))) {
		return -KVS_EINVAL;
	}

	if ((data == NULL) || (len == 0U)) {
		return 0;
	}

	off = ent->start + KVS_ALIGNDOWN(off, psize);

	/* fill remaining part of program buffer and write if needed */
	if (rem != 0) {
		const uint32_t rdlen = KVS_MIN(len, rem);
		uint8_t *buf = pbuf8 + (psize - rem);

		memcpy(buf, data8, rdlen);
		if (rdlen == rem) {
			rc = cfg->prog(cfg->ctx, off, pbuf8, psize);
			if (rc != 0) {
				goto end;
			}

			if (cfg->comp != NULL) {
				rc = cfg->comp(cfg->ctx, off, pbuf8, psize);
				if (rc != 0) {
					goto end;
				}
			}

			off += psize;
		}

		data8 += rdlen;
		len -= rdlen;
	}

	/* perform direct write if possible */
	if (len >= psize) {
		uint32_t wrlen = KVS_ALIGNDOWN(len, psize);

		rc = cfg->prog(cfg->ctx, off, data8, wrlen);
		if (rc != 0) {
			goto end;
		}

		if (cfg->comp != NULL) {
			rc = cfg->comp(cfg->ctx, off, data8, wrlen);
			if (rc != 0) {
				goto end;
			}
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

static int key_read_cb_entry(const void *ctx, uint32_t off, void *data, uint32_t len)
{
	struct kvs_ent *ent = (struct kvs_ent *)(ctx);

	return entry_read(ent, ent->key_start + off, data, len);
}

static int key_read_cb_const(const void *ctx, uint32_t off, void *data, uint32_t len)
{
	uint8_t *src = (uint8_t *)ctx;

	memcpy(data, src + off, len);
	return 0;
}

static bool key_starts_with(const struct kvs_ent *ent, const struct key_read_cb *rd)
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
		if (rc) {
			return false;
		}

		rc = rd->read(rd->ctx, off, bufr, rdlen);
		if (rc) {
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

static void block_retard(const struct kvs *kvs, uint32_t *pos)
{
	const struct kvs_cfg *cfg = kvs->cfg;

	*pos = KVS_ALIGNDOWN(*pos, cfg->bsize);
	if (*pos == 0U) {
		*pos = cfg->bsize * cfg->bcnt;
	}

	*pos -= cfg->bsize;
}

static void wblock_advance(const struct kvs *kvs)
{
	const struct kvs_cfg *cfg = kvs->cfg;
	struct kvs_data *data = kvs->data;

	data->pos = data->bend;
	if (data->pos == (cfg->bcnt * cfg->bsize)) {
		data->epoch++;
		data->pos = 0U;
	}

	data->bend = data->pos + cfg->bsize;
}

struct block_start_ext {
	uint32_t magic;
	uint32_t epoch;
};

static void entry_link(struct kvs_ent *ent, const struct kvs *kvs)
{
	ent->kvs_id = (uint32_t *)&kvs->id;
}

static int entry_take_write(struct kvs_ent *ent)
{
	const struct kvs *kvs = KVS_CONTAINER_OF(ent->kvs_id, struct kvs, id);
	struct kvs_data *data = kvs->data;
	const uint32_t psize = kvs->cfg->psize;
	const uint32_t elen = KVS_ALIGNDOWN(ent->val_start + ent->val_len, psize) + psize;
	
	if ((data->pos + elen) > data->bend) {
		return -KVS_ENOSPC;
	}

	ent->start = data->pos;
	ent->next = ent->start + elen;
	data->pos = ent->next;
	data->wr_ent = ent;
	return 0;
}

static void entry_release_write(struct kvs_ent *ent)
{
	const struct kvs *kvs = KVS_CONTAINER_OF(ent->kvs_id, struct kvs, id);
	struct kvs_data *data = kvs->data;

	data->wr_ent = NULL;
}

static int entry_create(struct kvs_ent *ent, uint32_t key_len, uint32_t val_len, uint8_t *hdr)
{
	const struct kvs *kvs = KVS_CONTAINER_OF(ent->kvs_id, struct kvs, id);
	const struct kvs_cfg *cfg = kvs->cfg;
	struct kvs_data *data = kvs->data;
	uint32_t ext_len;
	int rc;

	if (data->wr_ent != NULL) {
		return -KVS_EDEADLK;
	}

	if (data->pos == KVS_ALIGNDOWN(data->pos, cfg->bsize)) {
		ext_len = sizeof(struct block_start_ext);
	} else {
		ext_len = 0U;
	}

	make_entry_hdr(hdr, ext_len, key_len, val_len);
	
	ent->ext_start = entry_hdr_len(hdr);
	ent->key_start = ent->ext_start + ext_len;
	ent->val_start = ent->key_start + key_len;
	ent->val_len = val_len;

	return entry_take_write(ent);	
}

static int entry_add(struct kvs_ent *ent, const char *key, uint32_t val_len)
{
	const struct kvs *kvs = KVS_CONTAINER_OF(ent->kvs_id, struct kvs, id);
	const uint32_t key_len = strlen(key);
	const struct block_start_ext ext = {
		.magic = KVS_MAGIC,
		.epoch = kvs->data->epoch,
	};
	uint8_t hdr[KVS_MAXHDRSIZE];
	int rc;

	if (entry_create(ent, key_len, val_len, hdr) != 0) {
		return -KVS_ENOSPC;
	}

	rc = entry_write(ent, 0, hdr, ent->ext_start);
	if (rc != 0) {
		goto end;
	}

	if (ent->key_start != ent->ext_start) {
		rc = entry_write(ent, ent->ext_start, &ext, sizeof(struct block_start_ext));
		if (rc != 0) {
			goto end;
		}
	}

	rc = entry_write(ent, ent->key_start, key, key_len);
	if (rc != 0) {
		goto end;
	}

end:
	return rc;
}

static int entry_flush(struct kvs_ent *ent)
{
	const struct kvs *kvs = KVS_CONTAINER_OF(ent->kvs_id, struct kvs, id);
	const struct kvs_cfg *cfg = kvs->cfg;
	const uint8_t fill = KVS_FILLCHAR;
	uint32_t off = ent->val_start + ent->val_len;
	uint32_t len = ent->next - ent->start - off;
	int rc;

	while (len != 0U) {
		rc = entry_write(ent, off, &fill, 1);
		if (rc) {
			goto end;
		}

		len--;
		off++;
	}

	if (cfg->sync != NULL) {
		rc = cfg->sync(cfg->ctx);
	}

end:
	entry_release_write(ent);
	return rc;
}

static int entry_copy(const struct kvs_ent *ent)
{
	const struct kvs *kvs = KVS_CONTAINER_OF(ent->kvs_id, struct kvs, id);
	const struct block_start_ext ext = {
		.magic = KVS_MAGIC,
		.epoch = kvs->data->epoch,
	};
	struct kvs_ent cp_ent;
	uint32_t len, off;
	uint8_t buf[KVS_BUFSIZE];
	uint8_t hdr[KVS_MAXHDRSIZE];
	int rc;

	entry_link(&cp_ent, kvs);
	len = ent->val_start - ent->key_start;
	if (entry_create(&cp_ent, len, ent->val_len, hdr) != 0) {
		return -KVS_ENOSPC;
	}

	rc = entry_write(&cp_ent, 0, hdr, ent->ext_start);
	if (rc != 0) {
		goto end;
	}

	if (cp_ent.key_start != cp_ent.ext_start) {
		rc = entry_write(&cp_ent, cp_ent.ext_start, &ext, sizeof(struct block_start_ext));
		if (rc != 0) {
			goto end;
		}
	}

	len += ent->val_len;
	off = 0U;
	while (len != 0U) {
		const uint32_t rdlen = KVS_MIN(len, sizeof(buf));

		rc = entry_read(ent, ent->key_start + off, buf, rdlen);
		if (rc != 0) {
			goto end;
		}

		rc = entry_write(&cp_ent, cp_ent.key_start + off, buf, rdlen);
		if (rc != 0) {
			goto end;
		}
		len -= rdlen;
		off += rdlen;
	}

	return entry_flush(&cp_ent);

end:
	entry_release_write(&cp_ent);
	return rc;
}

static int get_next_in_block(struct kvs_ent *ent)
{
	const struct kvs *kvs = KVS_CONTAINER_OF(ent->kvs_id, struct kvs, id);
	const struct kvs_cfg *cfg = kvs->cfg;
	const uint32_t psize = cfg->psize;
	uint8_t hdr[KVS_MAXHDRSIZE], fill;
	uint32_t ext_len, key_len, val_len, ent_len;
	int rc;

	ent->start = ent->next;
	
	rc = entry_read(ent, 0, hdr, sizeof(hdr));
	if (rc != 0) {
		return rc;
	}

	rc = read_entry_hdr(hdr, &ext_len, &key_len, &val_len);
	if (rc != 0) {
		return rc;
	}

	ent_len = entry_hdr_len(hdr) + ext_len + key_len + val_len;

	rc = entry_read(ent, ent_len, &fill, 1);
	if ((rc != 0) || (fill != KVS_FILLCHAR)) {
		return -KVS_ENOENT;
	}

	ent->ext_start = entry_hdr_len(hdr);
	ent->key_start = ent->ext_start + ext_len;
	ent->val_start = ent->key_start + key_len;
	ent->val_len = val_len;
	ent->next = KVS_ALIGNDOWN(ent->start + ent_len, psize) + psize;

	return 0;
}

static int entry_get_info(struct kvs_ent *ent)
{
	const struct kvs *kvs = KVS_CONTAINER_OF(ent->kvs_id, struct kvs, id);
	const struct kvs_cfg *cfg = kvs->cfg;
	const uint32_t psize = cfg->psize;
	uint8_t hdr[KVS_MAXHDRSIZE], fill;
	uint32_t hdr_len, ext_len, key_len, val_len;
	int rc;

	ent->start = KVS_ALIGNUP(ent->start, psize);
	rc = entry_read(ent, 0, hdr, sizeof(hdr));
	if (rc != 0) {
		goto end;
	}

	rc = read_entry_hdr(hdr, &ext_len, &key_len, &val_len);
	if (rc != 0) {
		goto end;
	}

	hdr_len = entry_hdr_len(hdr);

	rc = entry_read(ent, hdr_len + ext_len + key_len + val_len, &fill, 1);
	if ((rc != 0) || (fill != KVS_FILLCHAR)) {
		goto end;
	}

	ent->ext_start = hdr_len;
	ent->key_start = ent->ext_start + ext_len;
	ent->val_start = ent->key_start + key_len;
	ent->val_len = val_len;
	ent->next = KVS_ALIGNDOWN(ent->val_start + ent->val_len + 1, psize) + psize;
	return 0;
end:
	return -KVS_ENOENT;
}

static int entry_match_in_block(struct kvs_ent *ent,
				bool (*match)(const struct kvs_ent *ent, void *arg), void *arg)
{
	const struct kvs *kvs = KVS_CONTAINER_OF(ent->kvs_id, struct kvs, id);
	const uint32_t bsize = kvs->cfg->bsize;
	const uint32_t bend = KVS_ALIGNDOWN(ent->start, bsize) + bsize;

	while (ent->next < bend) {
		ent->start = ent->next;
		if (entry_get_info(ent) != 0) {
			break;
		}
		if (match(ent, arg)) {
			return 0;
		}
	}

	return -KVS_ENOENT;
}

static int entry_zigzag_walk(struct kvs_ent *ent,
			     bool (*match)(const struct kvs_ent *ent, void *arg), void *arg)
{
	const struct kvs *kvs = KVS_CONTAINER_OF(ent->kvs_id, struct kvs, id);
	const struct kvs_cfg *cfg = kvs->cfg;
	const struct kvs_data *data = kvs->data;
	bool found = false;
	struct kvs_ent wlk;

	entry_link(&wlk, kvs);
	wlk.next = KVS_ALIGNDOWN(data->pos, cfg->bsize);

	for (int i = 0; i < (cfg->bcnt - cfg->bspr); i++) {
		wlk.start = wlk.next;
		while (entry_match_in_block(&wlk, match, arg) == 0) {
			found = true;
			memcpy(ent, &wlk, sizeof(struct kvs_ent));
		}

		if (found) {
			break;
		}

		wlk.next = KVS_ALIGNDOWN(wlk.start, cfg->bsize);
		if (wlk.next == 0U) {
			wlk.next = cfg->bsize * cfg->bcnt;
		}

		wlk.next -= cfg->bsize;
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

static int entry_get(struct kvs_ent *ent, const struct kvs *kvs, struct key_read_cb *rdkey)
{
	const struct kvs_cfg *cfg = kvs->cfg;
	struct kvs_data *data = kvs->data;

	entry_link(ent, kvs);
	ent->next = KVS_ALIGNDOWN(data->pos, cfg->bsize);
	ent->start = ent->next;
	
	if (entry_zigzag_walk(ent, match_key_exact, (void *)rdkey) == 0) {
		return 0;
	}
end:
	return -KVS_ENOENT;
}

static int entry_from_key(struct kvs_ent *ent, const struct kvs *kvs, const char *key)
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
	const uint32_t end = cfg->bcnt * cfg->bsize;

	struct kvs_ent wlk;
	int rc;

	entry_link(&wlk, kvs);
	wlk.next = (data->bend < end) ? data->bend : 0U;
	for (int i = 0; i < bcnt; i++) {
		wlk.start = wlk.next;
		while (entry_match_in_block(&wlk, match_key_start, (void *)rd) == 0) {
			struct key_read_cb rdwlkkey = {
				.len = wlk.val_start - wlk.key_start,
				.ctx = (void *)&wlk,
				.read = key_read_cb_entry,
			};
			struct kvs_ent last;

			if (entry_get(&last, kvs, &rdwlkkey) != 0) {
				continue;
			}

			if ((last.start == wlk.start) && (last.val_len != 0U)) {
				rc = cb->cb(&wlk, cb->cb_arg);
				if (rc) {
					goto end;
				}
			}
		}
		wlk.next = KVS_ALIGNDOWN(wlk.start, cfg->bsize) + cfg->bsize;
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
	const uint32_t end = cfg->bcnt * cfg->bsize;
	struct kvs_ent wlk;
	int rc;

	entry_link(&wlk, kvs);
	wlk.next = (data->bend < end) ? data->bend : 0U;
	for (int i = 0; i < bcnt; i++) {
		wlk.start = wlk.next;
		while (get_next_in_block(&wlk) != -KVS_ENOENT) {
			rc = cb->cb(&wlk, cb->cb_arg);
			if (rc) {
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
	const struct kvs *kvs = KVS_CONTAINER_OF(ent->kvs_id, struct kvs, id);
	int rc = 0;

	while (1) {
		rc = entry_copy(ent);
		if (rc != -KVS_ENOSPC) {
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
	struct key_read_cb rdkey = {
		.ctx = NULL,
	};
	struct entry_cb compact_entry_cb = {
		.cb = compact_walk_cb,
		.cb_arg = NULL,
	};

	if (data->pos != (data->bend - cfg->bsize)) {
		wblock_advance(kvs);
	}
	return entry_walk_unique(kvs, &rdkey, &compact_entry_cb, bcnt);
}

int kvs_entry_read(const struct kvs_ent *ent, uint32_t off, void *data, uint32_t len)
{
	return entry_read(ent, off, data, len);
}

int kvs_entry_get(struct kvs_ent *ent, const struct kvs *kvs, const char *key)
{
	if ((kvs == NULL) || (kvs->cfg == NULL)) {
		return -KVS_EINVAL;
	}

	return entry_from_key(ent, kvs, key);
}

int kvs_read(const struct kvs *kvs, const char *key, void *data, uint32_t len)
{
	if ((kvs == NULL) || (key == NULL) || (kvs->cfg == NULL)) {
		return -KVS_EINVAL;
	}

	struct kvs_ent wlk;

	if (kvs_entry_get(&wlk, kvs, key) == 0U) {
		uint32_t off = wlk.val_start;

		return entry_read(&wlk, off, data, len);
	}

	return -KVS_ENOENT;
}

int kvs_write(const struct kvs *kvs, const char *key, const void *data, uint32_t len)
{
	if ((kvs == NULL) || (key == NULL) || (kvs->cfg == NULL)) {
		return -KVS_EINVAL;
	}

	const struct kvs_cfg *cfg = kvs->cfg;
	struct kvs_ent ent;
	uint32_t cnt = cfg->bcnt - cfg->bspr;
	int rc;

	if (cfg->lock != NULL) {
		cfg->lock(cfg->ctx);
	}

	entry_link(&ent, kvs);
	while (cnt != 0U) {
		rc = entry_add(&ent, key, len);
		if (rc == 0) {
			break;
		}
		rc = compact(kvs, cfg->bcnt - cnt);
		if (rc != 0) {
			kvs->data->pos = kvs->data->bend;
		}
		cnt--;
	}

	if (kvs->data->wr_ent == NULL) {
		rc = -KVS_ENOSPC;
		goto end;
	}

	rc = entry_write(&ent, ent.val_start, data, len);
	if (rc) {
		goto end_write;
	}

	rc = entry_flush(&ent);
end_write:

end:
	if (cfg->unlock != NULL) {
		cfg->unlock(cfg->ctx);
	}

	return rc;
}

int kvs_delete(const struct kvs *kvs, const char *key)
{
	return kvs_write(kvs, key, NULL, 0);
}

int kvs_walk_unique(const struct kvs *kvs, const char *key, 
		    int (*cb)(const struct kvs_ent *ent, void *cb_arg), void *cb_arg)
{
	if ((kvs == NULL) || (kvs->cfg == NULL)) {
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
	if ((kvs == NULL) || (kvs->cfg == NULL)) {
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

int kvs_compact(const struct kvs *kvs)
{
	if ((kvs == NULL) || (kvs->cfg == NULL)) {
		return -KVS_EINVAL;
	}

	return compact(kvs, kvs->cfg->bcnt - kvs->cfg->bspr);
}

int kvs_mount(const struct kvs *kvs)
{
	/* basic config checks */
	if ((kvs == NULL) || (kvs->cfg == NULL) ||
	    (kvs->cfg->read == NULL) || (kvs->cfg->prog == NULL) || 
	    (kvs->cfg->psize == 0U) || (kvs->cfg->bcnt <= kvs->cfg->bspr) || 
	    (kvs->cfg->bsize == 0U) || ((kvs->cfg->bsize & (kvs->cfg->bsize - 1)) != 0U)) {
		return -KVS_EINVAL;
	}

	const struct kvs_cfg *cfg = kvs->cfg;
	const uint32_t end = cfg->bsize * cfg->bcnt;
	struct kvs_data *data = kvs->data;
	struct kvs_ent wlk;
	bool last_block_found = false;
	int rc = 0;

	if (cfg->init != NULL) {
		cfg->init(cfg->ctx);
	}

	if (cfg->lock != NULL) {
		cfg->lock(cfg->ctx);
	}

	data->pos = 0U;
	data->epoch = 0U;
	
	wlk.kvs_id = (uint32_t *)&kvs->id;
	wlk.next = 0U;

	while (wlk.next < end) {
		wlk.start = wlk.next;
		rc = get_next_in_block(&wlk);
		if (rc == 0) {
			struct block_start_ext extra;
			uint32_t rdlen = sizeof(struct block_start_ext);

			rc = entry_read(&wlk, wlk.ext_start, &extra, rdlen);
			if ((wlk.key_start - wlk.ext_start) != rdlen) {
				rc = -KVS_EDEADLK;
			}

			if (rc) {
				goto end;
			}

			if ((extra.epoch >= data->epoch) || (!last_block_found)) {
				data->pos = wlk.start;
				data->bend = wlk.start + cfg->bsize;
				data->epoch = extra.epoch;
				last_block_found = true;
			}
		}
		wlk.next = wlk.start + cfg->bsize;
	}

	wlk.next = data->pos;
	wlk.start = wlk.next;
	while (get_next_in_block(&wlk) != -KVS_ENOENT) {
		data->pos = wlk.next;
	}

end:
	if (cfg->unlock != NULL) {
		cfg->unlock(cfg->ctx);
	}

	printk("MOUNTED: fs->pos %d fs->bend %d fs->epoch %d\n", data->pos, data->bend, data->epoch);

	return rc;
}

int kvs_unmount(const struct kvs *kvs)
{
	return 0;
}