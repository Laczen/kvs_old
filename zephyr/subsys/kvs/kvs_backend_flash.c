/*
 * Copyright (c) 2023 Laczen
 *
 * KVS flash backend definition
 * 
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <errno.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/subsys/kvs.h>

#define LOG_LEVEL CONFIG_KVS_BACKEND_FLASH_LOG_LEVEL
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(kvs_backend_flash);

struct kvs_flash_be {
        const struct device *const fldev;
        const off_t floff;
        const size_t flsize;
        const size_t flfree;
        const size_t blsize;
        struct k_sem sem;
};

static int kvs_flash_be_read(const void *ctx, uint32_t off, void *data,
                             uint32_t len)
{
        const struct kvs_flash_be *fbe = (const struct kvs_flash_be *)ctx;
        const uint32_t floff = fbe->floff + off;
        int rc;

        if ((off + len) > fbe->flsize) {
                LOG_ERR("read out of bounds [%x - %d]", off, len);
                rc = -EINVAL;
                goto end;
        }

        rc = flash_read(fbe->fldev, floff, data, len);
end:
        LOG_DBG("read %d bytes at %x [%d]", len, floff, rc);
        return rc;
}

static int kvs_flash_be_prog(const void *ctx, uint32_t off, const void *data,
                             uint32_t len)
{
        struct kvs_flash_be *fbe = (struct kvs_flash_be *)ctx;
        const uint32_t floff = fbe->floff + off;
        struct flash_pages_info fp_info;
        int rc;

        if ((off + len) > fbe->flsize) {
                rc = -EINVAL;
                goto end;
        }

        if ((off % fbe->blsize) == 0U) {
                rc = flash_get_page_info_by_offs(fbe->fldev, floff, &fp_info);
                if (rc) {
                        LOG_ERR("failed to get page info");
                        goto end;
                }

                if (fp_info.start_offset == floff) {
                        size_t esize = MAX(fp_info.size, fbe->blsize);
                        rc = flash_erase(fbe->fldev, floff, esize);
                        if (rc) {
                                LOG_ERR("failed to erase %d bytes at %x",
                                        esize, floff);
                                goto end;
                        }

                }

        }

        rc = flash_write(fbe->fldev, floff, data, len);
end:
        LOG_DBG("prog %d bytes at %x [%d]", len, floff, rc);
        return rc;
}

static int kvs_flash_be_comp(const void *ctx, uint32_t off, const void *data,
                             uint32_t len)
{
        const uint8_t *data8 = (const uint8_t *)data;
        uint8_t buf[32];
        int rc;

        while (len != 0) {
                uint32_t rdlen = MIN(len, sizeof(buf));
                
                rc = kvs_flash_be_read(ctx, off, buf, rdlen);
                if (rc != 0) {
                        goto end;
                }

                if (memcmp(buf, data8, rdlen) != 0) {
                        rc = -EIO;
                        goto end;
                }

                len -= rdlen;
                off += rdlen;
                data8 += rdlen;
        }
end:
        LOG_DBG("comp %d bytes at %x [%d]", len, off, rc);
        return rc;
}

static int kvs_flash_be_sync(const void *ctx, uint32_t off)
{
        return 0;
}

static int kvs_flash_be_lock(const void *ctx)
{
        struct kvs_flash_be *fbe = (struct kvs_flash_be *)ctx;

        k_sem_take(&fbe->sem, K_FOREVER);
        return 0;
}

static int kvs_flash_be_unlock(const void *ctx)
{
        struct kvs_flash_be *fbe = (struct kvs_flash_be *)ctx;

        k_sem_give(&fbe->sem);
        return 0;
}

static int kvs_flash_be_init(const void *ctx)
{
        struct kvs_flash_be *fbe = (struct kvs_flash_be *)ctx;
        int rc = 0;
        off_t eboff = 0;
        size_t ebmin = fbe->flsize;
        size_t ebmax = 0U;
        struct flash_pages_info ebinfo;

        k_sem_init(&fbe->sem, 1, 1);
        kvs_flash_be_lock(ctx);
        while (eboff < fbe->flsize) {
                rc = flash_get_page_info_by_offs(fbe->fldev, fbe->floff + eboff,
                                                 &ebinfo);
                if (rc != 0) {
                        LOG_ERR("failed to get page info");
                        goto end;
                }

                if (ebinfo.start_offset != (fbe->floff + eboff)) {
                        LOG_ERR("partition is not aligned to erase-block-size");
                        rc = -EINVAL;
                        goto end;
                }

                if (ebinfo.size < ebmin) {
                        ebmin = ebinfo.size;
                }

                if (ebinfo.size > ebmax) {
                        ebmax = ebinfo.size;
                }

                eboff += ebinfo.size;
        }

        if (ebmax > fbe->flfree) {
                LOG_ERR("insufficient free space");
                rc = -EINVAL;
        }

end:
        kvs_flash_be_unlock(ctx);
        LOG_DBG("backend init [%d]", rc);
        return rc;
}

static int kvs_flash_be_release(const void *ctx)
{
        return 0;
}

#define KVS_PART(inst) DT_PHANDLE(inst, partition)
#define KVS_MTD(inst) DT_MTD_FROM_FIXED_PARTITION(KVS_PART(inst))
#define KVS_DEV(inst) DEVICE_DT_GET(KVS_MTD(inst))
#define KVS_SIZE(inst) DT_REG_SIZE(KVS_PART(inst))
#define KVS_OFF(inst) DT_REG_ADDR(KVS_PART(inst))
#define KVS_SSIZE(inst) DT_PROP(inst, sector_size)
#define KVS_FSIZE(inst)                                                         \
        COND_CODE_1(DT_NODE_HAS_PROP(inst, free_size),                          \
                    (DT_PROP(inst, free_size)), (DT_PROP(inst, sector_size)))
#define KVS_BCNT(inst) KVS_SIZE(inst)/KVS_SSIZE(inst)
#define KVS_FBCNT(inst) KVS_FSIZE(inst)/KVS_SSIZE(inst)
#define KVS_PBUFSIZE(inst)                                                      \
        COND_CODE_1(DT_NODE_HAS_PROP(KVS_MTD(inst), write_block_size),          \
                    (DT_PROP(KVS_MTD(inst), write_block_size)), (8))

#define KVS_CHECK_SSIZE(inst)                                                   \
        BUILD_ASSERT((KVS_SSIZE(inst) & (KVS_SSIZE(inst) - 1)) == 0,            \
                     "Sector size not a power of 2")
#define KVS_CHECK_SCNT(inst)                                                    \
        BUILD_ASSERT((KVS_SIZE(inst) % KVS_SSIZE(inst)) == 0,                   \
                     "Partition size not a multiple of sector size")
#define KVS_CHECK_FSCNT(inst)                                                   \
        BUILD_ASSERT((KVS_FSIZE(inst) % KVS_SSIZE(inst)) == 0,                  \
                     "Free size not a multiple of sector size")

#define KVS_FLASH_DEFINE(inst)                                                  \
        KVS_CHECK_SSIZE(inst);                                                  \
        KVS_CHECK_SCNT(inst);                                                   \
        KVS_CHECK_FSCNT(inst);                                                  \
        struct kvs_flash_be kvs_flash_be_##inst = {                             \
                .fldev = KVS_DEV(inst),                                         \
                .floff = KVS_OFF(inst),                                         \
                .flsize = KVS_SIZE(inst),                                       \
                .flfree = KVS_FSIZE(inst),                                      \
                .blsize = KVS_SSIZE(inst),                                      \
        };                                                                      \
        uint8_t kvs_flash_be_pbuf_##inst[KVS_PBUFSIZE(inst)];                   \
        DEFINE_KVS(                                                             \
                inst, KVS_SSIZE(inst), KVS_BCNT(inst), KVS_FBCNT(inst),         \
                &kvs_flash_be_##inst, (void *)&kvs_flash_be_pbuf_##inst,        \
                KVS_PBUFSIZE(inst), kvs_flash_be_read, kvs_flash_be_prog,       \
                kvs_flash_be_comp, kvs_flash_be_sync, kvs_flash_be_init,        \
                kvs_flash_be_release, kvs_flash_be_lock, kvs_flash_be_unlock    \
        );
        
DT_FOREACH_STATUS_OKAY(zephyr_kvs_flash, KVS_FLASH_DEFINE)