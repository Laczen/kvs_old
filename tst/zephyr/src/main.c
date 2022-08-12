#include <stdarg.h>
#include "zephyr/zephyr.h"
#include "zephyr/ztest.h"
#include "zephyr/sys/printk.h"
#include "kvs/kvs.h"


uint8_t back[1280];
uint8_t pbuf[8];

static int read(void *ctx, uint32_t off, void *data, uint32_t len)
{
        uint8_t *data8 = (uint8_t *)data;

        if ((off + len) > sizeof(back)) {
                return -KVS_EIO;
        }

        // if ((offset >= 256) && (offset < 512)) {
        //         return -KVS_EIO;
        // }

        memcpy(data8, &back[off], len);
        return 0;
}

static int prog(void *ctx, uint32_t off, const void *data, uint32_t len)
{
        const uint8_t *data8 = (uint8_t *)data;

        if ((off + len) > sizeof(back)) {
                return -KVS_EIO;
        }

        if ((off >= 256) && (off < 512)) {
                return -KVS_EIO;
        }

        if (off % 256 == 0) {
                memset(&back[off], 0, 256);
        }

        memcpy(&back[off], data8, len);
        return 0;
}

static int comp(void *ctx, uint32_t off, const void *data, uint32_t len)
{
        const uint8_t *data8 = (uint8_t *)data;

        if (memcmp(&back[off], data8, len) != 0) {
                return -KVS_EIO;
        }

        return 0;
}

DEFINE_KVS(test, 256, 5, 2, NULL, (void *)&pbuf, 4, read, prog, comp, NULL,
           NULL, NULL, NULL, NULL);

int kvs_walk_cb(const struct kvs_ent *ent, void *cb_arg)
{
        char buf[12];
        uint32_t rdlen = KVS_MIN(sizeof(buf), ent->val_start - ent->key_start);

        kvs_entry_read(ent, ent->key_start, buf, rdlen);
        buf[KVS_MIN(11, ent->val_start - ent->key_start)]= '\0';
        printk("Found entry at %d named %s\n", ent->start, buf);
        return 0;
}

void test_main(void)
{
        int rc;
        struct kvs *kvs = GET_KVS(test);
        struct kvs_ent entry;
        uint8_t tstdata[256];
        uint8_t rddata[256];

        kvs_mount(kvs);
        printk("Mounted pos %d bend %d", kvs->data->pos, kvs->data->bend);

        printk("Testing\n");
        uint8_t cnt = 96;

        while ((kvs->data->epoch == 0) && (--cnt > 0U)) {
                rc = kvs_write(kvs, "testkep", &tstdata, 234);
                if (rc == -KVS_ENOSPC) {
                        break;
                }
        }

        printk("Calling walk unique\n");
        kvs_walk_unique(kvs, "t", kvs_walk_cb, NULL);
        printk("Calling walk\n");
        kvs_walk(kvs, "t", kvs_walk_cb, NULL);
        kvs_mount(kvs);

        printk("cnt: %d\n", cnt);
        rc = kvs_write(kvs, "testkey", tstdata, 1);

        memcpy(tstdata, "datatsttst", 10);
        rc = kvs_write(kvs, "testit", tstdata, 12);

        memcpy(tstdata, "dayatst", 7);

        rc = kvs_write(kvs, "testit", tstdata, 7);

        printk("Doing read\n");
        rc = kvs_read(kvs, "testit", rddata, sizeof(tstdata));
        printk("Read result: %d data %s\n", rc, rddata);

        uint8_t tst;
        rc = kvs_read(kvs, "testkey", &tst, sizeof(tst));
        printk("Read result: %d %x\n", rc, tst);

        rc = kvs_read(kvs, "test", &tst, sizeof(tst));
        printk("Read result: %d %x\n", rc, tst);

        rc = kvs_read(kvs, "testkep", &rddata, sizeof(tstdata));
        printk("Read result: %d %s\n", rc, rddata);

        // printk("Testing gc\n");
        // for (int i = 0; i < 96; i++) {
        //         rc = kvs_write(kvs, "testit1", tstdata, 12);
        // }

        kvs_mount(kvs);
        // printk("Calling kvs_walk\n");
        // kvs_walk(kvs, "", kvs_walk_cb, NULL);

        // printk("Calling kvs_walk_unique\n");
        // kvs_walk_unique(kvs, "", kvs_walk_cb, NULL);
        // printk("Calling kvs_walk_unique\n");
        // kvs_walk_unique(&kvs, "testit", kvs_walk_cb, NULL);
        // printk("fs->pos %d, fs->epoch %d\n", kvs->data->pos, kvs->data->epoch);
        // printk("Calling compact...\n");
        // kvs_compact(&kvs);
        // printk("fs->pos %d, fs->epoch %d\n", kvs->data->pos, kvs->data->epoch);
        // printk("Calling kvs_walk_unique\n");
        // kvs_walk_unique(kvs, "", kvs_walk_cb, NULL);

        // kvs_mount(kvs);

}