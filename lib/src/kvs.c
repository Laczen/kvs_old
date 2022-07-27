/*
 * Key Value Store
 *
 * Copyright (c) 2022 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "kvs/kvs.h"

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

static void read_entry_hdr(const uint8_t *hdr, uint32_t *elen, uint32_t *klen, uint32_t *vlen)
{
	uint8_t *s = (uint8_t *)hdr;

	*elen = 0U;
	*klen = 0U;
	*vlen = 0U;

	if (((*s++) & KVS_HDRSTART_MASK) != KVS_HDRSTART) {
		return;
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
}

static int entry_read(const struct kvs_ent *ent, uint32_t off, void *data, uint32_t len)
{
	const struct kvs_fs *fs = KVS_CONTAINER_OF(ent->pos, struct kvs_fs, pos);
	const uint32_t bsize = fs->bsize;
	const uint32_t bend = KVS_ALIGNDOWN(ent->start, bsize) + bsize;
	const struct kvs_fs_cfg *cfg = fs->cfg;

	len = KVS_MIN(len, bend - (ent->start + off));
	return cfg->read(cfg->ctx, ent->start + off, data, len);
}

static int entry_write(struct kvs_ent *ent, uint32_t off, const void *data, uint32_t len)
{
	struct kvs_fs *fs = KVS_CONTAINER_OF(ent->pos, struct kvs_fs, pos);
	const struct kvs_fs_cfg *cfg = fs->cfg;
	const uint32_t psize = cfg->psize;
	const uint32_t rem = KVS_ALIGNUP(off, psize) - off;
	uint8_t *pbuf8 = (uint8_t *)cfg->pbuf;
	uint8_t *data8 = (uint8_t *)data;
	int rc = 0;

	if ((fs->wr_ent != ent) || ((ent->next - ent->start) < (off + len))) {
		return -KVS_EINVAL;
	}

	off = ent->start + KVS_ALIGNDOWN(off, psize);

        /* fill remaining part of program buffer and write if needed */
	if (rem != 0) {
		const uint32_t rdlen = KVS_MIN(len, rem);
		uint8_t *buf = pbuf8 + (psize - rem);

		memcpy(buf, data8, rdlen);
		if (rdlen == rem) {
			rc = cfg->prog(cfg->ctx, off, pbuf8, psize);
			if (rc) {
				return rc;
			}

			if (cfg->comp != NULL) {
				rc = cfg->comp(cfg->ctx, off, pbuf8, psize);
				if (rc) {
					return rc;
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
		if (rc) {
			return rc;
		}

		if (cfg->comp != NULL) {
			rc = cfg->comp(cfg->ctx, off, data8, wrlen);
			if (rc) {
				return rc;
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

static void block_retard(const struct kvs_fs *fs, uint32_t *pos)
{
	*pos = KVS_ALIGNDOWN(*pos, fs->bsize);
	if (*pos == 0U) {
		*pos = fs->bsize * fs->bcnt;
	}

	*pos -= fs->bsize;
}

static void wblock_advance(const struct kvs_fs *fs)
{
	struct kvs_fs *fsw = (struct kvs_fs *)fs;

	fsw->pos = fsw->bend;
	if (fsw->pos == (fsw->bcnt * fsw->bsize)) {
		fsw->epoch++;
		fsw->pos = 0U;
	}

	fsw->bend = fsw->pos + fsw->bsize;
}

static int key_hash(const struct kvs_fs *fs, struct key_read_cb *rd, uint32_t *hash)
{
	uint32_t hashvalue, len, off;
	int rc = 0;

	hashvalue = 0U;
	if (fs->cfg->hash == NULL) {
		goto end;
	}

	len = rd->len;
	off = 0U;

	while (len != 0) {
		uint8_t buf[KVS_BUFSIZE];
		uint32_t rdlen = KVS_MIN(len, sizeof(buf));

		rc = rd->read(rd->ctx, off, buf, rdlen);
		if (rc) {
			hashvalue = 0U;
			goto end;
		}

		hashvalue = fs->cfg->hash(buf, rdlen, hashvalue);
		off += rdlen;
		len -= rdlen;
	}
end:
	*hash = hashvalue;
	return rc;
}

struct block_start_ext {
	uint32_t magic;
	uint32_t epoch;
};

static int entry_create(struct kvs_ent *ent, struct kvs_fs *fs, uint32_t key_len, uint32_t val_len)
{
	if (fs->wr_ent != NULL) {
		return -KVS_EDEADLK;
	}

	const struct block_start_ext extra = {
		.magic = KVS_MAGIC,
		.epoch = fs->epoch,
	};
	const uint32_t psize = fs->cfg->psize;
	uint8_t hdr[KVS_MAXHDRSIZE];
	uint32_t hdr_len, ext_len, entry_len, next;
	int rc;

	if (fs->pos == KVS_ALIGNDOWN(fs->pos, fs->bsize)) {
		ext_len = sizeof(struct block_start_ext);
	} else {
		ext_len = 0U;
	}

	make_entry_hdr(hdr, ext_len, key_len, val_len);
	hdr_len = entry_hdr_len(hdr);
	entry_len = hdr_len + ext_len + key_len + val_len;
	next = KVS_ALIGNDOWN(fs->pos + entry_len, psize) + psize;

	if (next > fs->bend) {
		return -KVS_ENOSPC;
	}

	fs->wr_ent = ent;
	ent->pos = (uint32_t *)&fs->pos;
	ent->start = fs->pos;
	ent->ext_start = hdr_len;
	ent->key_start = ent->ext_start + ext_len;
	ent->val_start = ent->key_start + key_len;
	ent->val_len = val_len;
	ent->next = next;
	fs->pos = next;

	rc = entry_write(ent, 0, hdr, hdr_len);
	if (rc) {
		goto end;
	}

	rc = entry_write(ent, ent->ext_start, &extra, ext_len);
end:
	return rc;
}

static int entry_add(struct kvs_ent *ent, struct kvs_fs *fs, const char *key, uint32_t val_len)
{
	const uint32_t key_len = strlen(key);
	int rc;

	rc = entry_create(ent, fs, key_len, val_len);
	if (rc) {
		goto end;
	}

	rc = entry_write(ent, ent->key_start, key, key_len);

end:
	return rc;
}

static int entry_flush(struct kvs_ent *ent)
{
	struct kvs_fs *fs = KVS_CONTAINER_OF(ent->pos, struct kvs_fs, pos);
	const struct kvs_fs_cfg *cfg = fs->cfg;
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
		if (rc) {
			goto end;
		}
	}

	if (cfg->hash_set_block_addr != NULL) {
		struct key_read_cb rd_key = {
			.len = ent->val_start - ent->key_start,
			.ctx = (void *)ent,
			.read = key_read_cb_entry,
		};
		uint32_t hash;

		rc = key_hash(fs, &rd_key, &hash);
		if (rc) {
			goto end;
		}
		cfg->hash_set_block_addr(hash, ent->start / fs->bsize);
	}

end:
	fs->wr_ent = NULL;
	return rc;
}

static int entry_copy(const struct kvs_ent *ent)
{
	struct kvs_fs *fs = KVS_CONTAINER_OF(ent->pos, struct kvs_fs, pos);
	struct kvs_ent cp_ent;
	uint32_t len, off;
	uint8_t buf[KVS_BUFSIZE];
	int rc;

	len = ent->val_start - ent->key_start;
	rc = entry_create(&cp_ent, fs, len, ent->val_len);
	if (rc) {
		goto end;
	}

	len += ent->val_len;
	off = 0U;
	while (len != 0U) {
		const uint32_t rdlen = KVS_MIN(len, sizeof(buf));

		rc = entry_read(ent, ent->key_start + off, buf, rdlen);
		if (rc) {
			goto end;
		}

		rc = entry_write(&cp_ent, cp_ent.key_start + off, buf, rdlen);
		if (rc) {
			goto end;
		}
		len -= rdlen;
		off += rdlen;
	}

	rc = entry_flush(&cp_ent);

end:
	return rc;
}

static int entry_advance_in_block(struct kvs_ent *ent)
{
	const struct kvs_fs *fs = KVS_CONTAINER_OF(ent->pos, struct kvs_fs, pos);
	const uint32_t bend = KVS_ALIGNDOWN(ent->start, fs->bsize) + fs->bsize;
	const uint32_t psize = fs->cfg->psize;
	uint8_t hdr[KVS_MAXHDRSIZE], fill;
	uint32_t ext_len, key_len, val_len, ent_len;
	int rc;

	if (ent->next >= bend) {
		return -KVS_ENOENT;
	}

	ent->start = ent->next;
	ent->next = bend;

	rc = entry_read(ent, 0, hdr, sizeof(hdr));
	if (rc) {
		return rc;
	}

	read_entry_hdr(hdr, &ext_len, &key_len, &val_len);
	if (key_len == 0U) {
		return -KVS_ENOENT;
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

static int entry_match_in_block(struct kvs_ent *ent,
				bool (*match)(const struct kvs_ent *ent, void *arg), void *arg)
{
	while (entry_advance_in_block(ent) != -KVS_ENOENT) {
		if (match(ent, arg)) {
			return 0;
		}
	}

	return -KVS_ENOENT;
}

static int entry_zigzag_walk(struct kvs_ent *ent,
			     bool (*match)(const struct kvs_ent *ent, void *arg), void *arg)
{
	const struct kvs_fs *fs = KVS_CONTAINER_OF(ent->pos, struct kvs_fs, pos);
	bool found = false;
	struct kvs_ent wlk;

	memcpy(&wlk, ent, sizeof(struct kvs_ent));

	while (true) {
		while (entry_match_in_block(&wlk, match, arg) == 0) {
			found = true;
			memcpy(ent, &wlk, sizeof(struct kvs_ent));
		}

		if (found) {
			break;
		}

		block_retard(fs, &wlk.next);
		block_retard(fs, &wlk.next);
		if (wlk.next == (fs->bend - fs->bsize)) {
			break;
		}
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

static int entry_get(struct kvs_ent *ent, const struct kvs_fs *fs, struct key_read_cb *rdkey)
{
	const struct kvs_fs_cfg *cfg = fs->cfg;

	ent->pos = (uint32_t *)&fs->pos;
	ent->start = KVS_ALIGNDOWN(fs->pos, fs->bsize);
	ent->next = ent->start;

	if (cfg->hash_get_block_addr != NULL) {
		uint32_t hash;
		if (key_hash(fs, rdkey, &hash) == 0) {
			uint32_t block = cfg->hash_get_block_addr(hash);
			if (block >= fs->bcnt) {
				goto end;
			}

			ent->next = block * fs->bsize;
			ent->start = ent->next;
		}
	}

	if (entry_zigzag_walk(ent, match_key_exact, (void *)rdkey) == 0) {
		return 0;
	}
end:
	return -KVS_ENOENT;
}

static int entry_from_key(struct kvs_ent *ent, const struct kvs_fs *fs, const char *key)
{
	struct key_read_cb rdkey = {
		.len = strlen(key),
		.ctx = (void *)key,
		.read = key_read_cb_const,
	};

	return entry_get(ent, fs, &rdkey);
}

static int entry_walk_unique(const struct kvs_fs *fs, struct key_read_cb *rd,
			     int (*entry_cb)(const struct kvs_ent *entry), uint32_t bcnt)
{
	struct kvs_ent wlk;
	int rc;

	wlk.pos = (uint32_t *)&fs->pos;
	wlk.next = (fs->bend < (fs->bcnt * fs->bsize)) ? fs->bend : 0U;
	for (int i = 0; i < bcnt; i++) {
		wlk.start = wlk.next;
		while (entry_match_in_block(&wlk, match_key_start, (void *)rd) != -KVS_ENOENT) {
			struct key_read_cb rdwlkkey = {
				.len = wlk.val_start - wlk.key_start,
				.ctx = (void *)&wlk,
				.read = key_read_cb_entry,
			};
			struct kvs_ent last;

			if (entry_get(&last, fs, &rdwlkkey) != 0) {
				continue;
			}

			if ((last.start == wlk.start) && (last.val_len != 0U)) {
				rc = entry_cb(&wlk);
				if (rc) {
					goto end;
				}
			}
		}

		wlk.next = (wlk.next < (fs->bcnt * fs->bsize)) ? wlk.next : 0U;
	}
end:
	return rc;
}

static int entry_walk(const struct kvs_fs *fs, struct key_read_cb *rd,
		      int (*entry_cb)(const struct kvs_ent *entry), uint32_t bcnt)
{
	struct kvs_ent wlk;
	int rc;

	wlk.pos = (uint32_t *)&fs->pos;
	wlk.next = (fs->bend < (fs->bcnt * fs->bsize)) ? fs->bend : 0U;
	for (int i = 0; i < bcnt; i++) {
		wlk.start = wlk.next;
		while (entry_advance_in_block(&wlk) != -KVS_ENOENT) {
			rc = entry_cb(&wlk);
			if (rc) {
				goto end;
			}
		}

		wlk.next = (wlk.next < (fs->bcnt * fs->bsize)) ? wlk.next : 0U;
	}
end:
	return rc;
}

static int gc_walk_cb(const struct kvs_ent *ent)
{
	struct kvs_fs *fs = KVS_CONTAINER_OF(ent->pos, struct kvs_fs, pos);
	int rc = 0;

	while (1) {
		rc = entry_copy(ent);
		if (rc != -KVS_ENOSPC) {
			break;
		}
		wblock_advance(fs);
	}

	return rc;
}

static int gc(const struct kvs_fs *fs)
{
	struct key_read_cb rdkey = {
		.ctx = NULL,
	};

	return entry_walk_unique(fs, &rdkey, &gc_walk_cb, fs->bspr);
}

static int compact(const struct kvs_fs *fs)
{
	struct key_read_cb rdkey = {
		.ctx = NULL,
	};

	if (fs->pos != (fs->bend - fs->bsize)) {
		wblock_advance(fs);
	}
	return entry_walk_unique(fs, &rdkey, &gc_walk_cb, fs->bcnt);
}

int kvs_entry_read(const struct kvs_ent *ent, uint32_t off, void *data, uint32_t len)
{
	return entry_read(ent, off, data, len);
}

int kvs_entry_write(struct kvs_ent *ent, uint32_t off, const void *data, uint32_t len)
{
	return entry_write(ent, off, data, len);
}

int kvs_entry_add(struct kvs_ent *ent, struct kvs_fs *fs, const char *key, uint32_t val_len)
{
	if ((ent == NULL) || (fs == NULL) || (key == NULL)) {
		return -KVS_EINVAL;
	}

	const struct kvs_fs_cfg *cfg = fs->cfg;
	uint32_t gc_cnt = fs->bcnt;
	int rc;

	if (cfg->lock != NULL) {
		cfg->lock(cfg->ctx);
	}

	while ((entry_add(ent, fs, key, val_len) == -KVS_ENOSPC) && (gc_cnt != 0U)) {
		wblock_advance(fs);
		rc = gc(fs);
		if (rc) {
			goto end;
		}
		gc_cnt--;
	}

	if (fs->wr_ent == NULL) {
		rc = -KVS_ENOSPC;
		goto end;
	}

	rc = 0;
end:
	if (cfg->unlock != NULL) {
		cfg->unlock(cfg->ctx);
	}

	return rc;
}

int kvs_entry_flush(struct kvs_ent *ent)
{
	const struct kvs_fs *fs = KVS_CONTAINER_OF(ent->pos, struct kvs_fs, pos);
	const struct kvs_fs_cfg *cfg = fs->cfg;
	int rc;

	if (cfg->lock != NULL) {
		cfg->lock(cfg->ctx);
	}

	rc = entry_flush(ent);

	if (cfg->unlock != NULL) {
		cfg->unlock(cfg->ctx);
	}

	return rc;
}

int kvs_entry_get(struct kvs_ent *ent, const struct kvs_fs *fs, const char *key)
{
	return entry_from_key(ent, fs, key);
}

int kvs_read(const struct kvs_fs *fs, const char *key, void *data, uint32_t len)
{
	if ((fs == NULL) || (key == NULL) || (fs->cfg == NULL)) {
		return -KVS_EINVAL;
	}

	struct kvs_ent wlk;

	if (kvs_entry_get(&wlk, fs, key) == 0U) {
		uint32_t off = wlk.val_start;

		return entry_read(&wlk, off, data, len);
	}

	return -KVS_ENOENT;
}

int kvs_walk_unique(const struct kvs_fs *fs, const char *key, int (*cb)(const struct kvs_ent *ent))
{
	struct key_read_cb rdkey = {
		.ctx = (void *)key,
		.len = strlen(key),
		.read = key_read_cb_const,
	};

	return entry_walk_unique(fs, &rdkey, cb, fs->bcnt);
}

int kvs_walk(const struct kvs_fs *fs, const char *key, int (*cb)(const struct kvs_ent *ent))
{
	struct key_read_cb rdkey = {
		.ctx = (void *)key,
		.len = strlen(key),
		.read = key_read_cb_const,
	};

	return entry_walk(fs, &rdkey, cb, fs->bcnt);
}

int kvs_write(const struct kvs_fs *kvs_fs, const char *key, const void *data, uint32_t len)
{
	return 0;
}

int kvs_init_hash_table(const struct kvs_fs *fs)
{
	const struct kvs_fs_cfg *cfg = fs->cfg;

	if (cfg->hash_init_block_addr != NULL) {
		cfg->hash_init_block_addr(KVS_INVALID_ADDR / fs->bsize);
	}

	return 0;
}

int kvs_compact(const struct kvs_fs *fs)
{
	return compact(fs);
}

int kvs_mount(const struct kvs_fs *fs)
{
	return 0;
}

int kvs_unmount(const struct kvs_fs *fs)
{
	return 0;
}