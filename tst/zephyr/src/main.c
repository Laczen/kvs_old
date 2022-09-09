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

        // if ((off >= 256) && (off < 512)) {
        //         return -KVS_EIO;
        // }

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

DEFINE_KVS(test, 256, 5, 1, NULL, (void *)&pbuf, 4, read, prog, comp, NULL,
           NULL, NULL, NULL, NULL);

ZTEST_SUITE(kvs_tests, NULL, NULL, NULL, NULL, NULL);

ZTEST(kvs_tests, kvs_mount)
{
        struct kvs *kvs = GET_KVS(test);
        int rc;

        (void)kvs_unmount(kvs);
        rc = kvs_mount(kvs);
        zassert_false(rc != 0, "mount failed [%d]", rc);
        rc = kvs_unmount(kvs);
        zassert_false(rc != 0, "unmount failed [%d]", rc);
}

ZTEST(kvs_tests, kvs_rw)
{
        struct kvs *kvs = GET_KVS(test);
        uint32_t cnt, rd_cnt;
        int rc;

        (void)kvs_unmount(kvs);
        rc = kvs_mount(kvs);
        zassert_false(rc != 0, "mount failed [%d]", rc);

        cnt = 0U;
        rc = kvs_write(kvs, "/cnt", &cnt, sizeof(cnt));
        zassert_false(rc != 0, "write failed [%d]", rc);

        rd_cnt = cnt + 1U;
        rc = kvs_read(kvs, "/cnt", &rd_cnt, sizeof(rd_cnt));
        zassert_false(rc != 0, "read failed [%d]", rc);
        zassert_false(rd_cnt != cnt, "wrong read value");

        cnt++;
        rc = kvs_write(kvs, "/cnt", &cnt, sizeof(cnt));
        zassert_false(rc != 0, "write failed [%d]", rc);

        rd_cnt = cnt + 1U;
        rc = kvs_read(kvs, "/cnt", &rd_cnt, sizeof(rd_cnt));
        zassert_false(rc != 0, "read failed [%d]", rc);
        zassert_false(rd_cnt != cnt, "wrong read value");

        rc = kvs_unmount(kvs);
        zassert_true(rc == 0, "unmount failed [%d]", rc);
}

ZTEST(kvs_tests, kvs_remount)
{
        struct kvs *kvs = GET_KVS(test);
        uint32_t cnt, pos, bend, epoch;
        int rc;

        (void)kvs_unmount(kvs);
        rc = kvs_mount(kvs);
        zassert_false(rc != 0, "mount failed [%d]", rc);

        cnt = 0U;
        rc = kvs_write(kvs, "/cnt", &cnt, sizeof(cnt));
        zassert_false(rc != 0, "write failed [%d]", rc);

        pos = kvs->data->pos;
        bend = kvs->data->bend;
        epoch = kvs->data->epoch;

        rc = kvs_unmount(kvs);
        zassert_true(rc == 0, "unmount failed [%d]", rc);

        rc = kvs_mount(kvs);
        zassert_false(rc != 0, "mount failed [%d]", rc);
        zassert_false(pos != kvs->data->pos, "wrong kvs->data->pos");
        zassert_false(bend != kvs->data->bend, "wrong kvs->data->bend");
        zassert_false(epoch != kvs->data->epoch, "wrong kvs->data->epoch");

        rc = kvs_unmount(kvs);
        zassert_true(rc == 0, "unmount failed [%d]", rc);
}

int kvs_walk_test_cb(const struct kvs_ent *ent, void *cb_arg)
{
        uint32_t *cnt = (uint32_t *)cb_arg;

        (*cnt) += 1;
        return 0;
}

ZTEST(kvs_tests, kvs_walk)
{
        struct kvs *kvs = GET_KVS(test);
        uint32_t cnt, en_cnt;
        int rc;

        cnt = 0U;
        (void)kvs_unmount(kvs);
        rc = kvs_mount(kvs);
        zassert_false(rc != 0, "mount failed [%d]", rc);

        /*
         * write one entry "/wlk_tst", walk searching for "/wlk_tst" and
         * count appearances, this should be one
         */
        rc = kvs_write(kvs, "/wlk_tst", &cnt, sizeof(cnt));
        zassert_false(rc != 0, "write failed [%d]", rc);
        en_cnt = 0U;
        rc = kvs_walk(kvs, "/wlk_tst", kvs_walk_test_cb, (void *)&en_cnt);
        zassert_false(rc != 0, "walk failed [%d]", rc);
        zassert_false(en_cnt != 1U, "wrong walk result value");

        /*
         * write another entry "/wlk_tst", walk searching for "/wlk_tst" and
         * count appearances, this should now be two
         */
        rc = kvs_write(kvs, "/wlk_tst", &cnt, sizeof(cnt));
        zassert_false(rc != 0, "write failed [%d]", rc);
        en_cnt = 0U;
        rc = kvs_walk(kvs, "/wlk_tst", kvs_walk_test_cb, (void *)&en_cnt);
        zassert_false(rc != 0, "walk failed [%d]", rc);
        zassert_false(en_cnt != 2U, "wrong walk result value");
}

ZTEST(kvs_tests, kvs_gc)
{
        struct kvs *kvs = GET_KVS(test);
        uint32_t cnt, epoch;
        int rc;

        (void)kvs_unmount(kvs);
        rc = kvs_mount(kvs);
        zassert_false(rc != 0, "mount failed [%d]", rc);

        cnt = 0U;
        rc = kvs_write(kvs, "/cnt", &cnt, sizeof(cnt));
        zassert_false(rc != 0, "write failed [%d]", rc);
        epoch = kvs->data->epoch;

        while (kvs->data->epoch == epoch) {
                cnt++;
                rc = kvs_write(kvs, "/cnt_", &cnt, sizeof(cnt));
                zassert_false(rc != 0, "write failed [%d]", rc);
        }

        rc = kvs_read(kvs, "/cnt_", &cnt, sizeof(cnt));
        zassert_false(rc != 0, "read failed [%d]", rc);

        rc = kvs_read(kvs, "/cnt", &cnt, sizeof(cnt));
        zassert_false(rc != 0, "read failed [%d]", rc);
        zassert_false(cnt != 0U, "wrong read value");

        rc = kvs_write(kvs, "/cnt", NULL, 0);
        zassert_false(rc != 0, "write failed [%d]", rc);
        epoch = kvs->data->epoch;

        while (kvs->data->epoch == epoch) {
                cnt++;
                rc = kvs_write(kvs, "/cnt_", &cnt, sizeof(cnt));
                zassert_false(rc != 0, "write failed [%d]", rc);
        }

        rc = kvs_read(kvs, "/cnt", &cnt, sizeof(cnt));
        zassert_false(rc == 0, "read succeeded on deleted item");

        rc = kvs_unmount(kvs);
        zassert_true(rc == 0, "unmount failed [%d]", rc);
}

// void test_main(void)
// {
//         int rc;
//         struct kvs *kvs = GET_KVS(test);
//         struct kvs_ent entry;
//         uint8_t tstdata[256];
//         uint8_t rddata[256];

//         kvs_mount(kvs);
//         printk("Mounted pos %d bend %d", kvs->data->pos, kvs->data->bend);

//         printk("Testing\n");
//         uint8_t cnt = 96;

//         while ((kvs->data->epoch == 0) && (--cnt > 0U)) {
//                 rc = kvs_write(kvs, "testkep", &tstdata, 234);
//                 if (rc == -KVS_ENOSPC) {
//                         break;
//                 }
//         }

//         printk("Calling walk unique\n");
//         kvs_walk_unique(kvs, "t", kvs_walk_cb, NULL);
//         printk("Calling walk\n");
//         kvs_walk(kvs, "t", kvs_walk_cb, NULL);
//         kvs_mount(kvs);

//         printk("cnt: %d\n", cnt);
//         rc = kvs_write(kvs, "testkey", tstdata, 1);

//         memcpy(tstdata, "datatsttst", 10);
//         rc = kvs_write(kvs, "testit", tstdata, 12);

//         memcpy(tstdata, "dayatst", 7);

//         rc = kvs_write(kvs, "testit", tstdata, 7);

//         printk("Doing read\n");
//         rc = kvs_read(kvs, "testit", rddata, sizeof(tstdata));
//         printk("Read result: %d data %s\n", rc, rddata);

//         uint8_t tst;
//         rc = kvs_read(kvs, "testkey", &tst, sizeof(tst));
//         printk("Read result: %d %x\n", rc, tst);

//         rc = kvs_read(kvs, "test", &tst, sizeof(tst));
//         printk("Read result: %d %x\n", rc, tst);

//         rc = kvs_read(kvs, "testkep", &rddata, sizeof(tstdata));
//         printk("Read result: %d %s\n", rc, rddata);

//         // printk("Testing gc\n");
//         // for (int i = 0; i < 96; i++) {
//         //         rc = kvs_write(kvs, "testit1", tstdata, 12);
//         // }

//         kvs_mount(kvs);
//         // printk("Calling kvs_walk\n");
//         // kvs_walk(kvs, "", kvs_walk_cb, NULL);

//         // printk("Calling kvs_walk_unique\n");
//         // kvs_walk_unique(kvs, "", kvs_walk_cb, NULL);
//         // printk("Calling kvs_walk_unique\n");
//         // kvs_walk_unique(&kvs, "testit", kvs_walk_cb, NULL);
//         // printk("fs->pos %d, fs->epoch %d\n", kvs->data->pos, kvs->data->epoch);
//         // printk("Calling compact...\n");
//         // kvs_compact(&kvs);
//         // printk("fs->pos %d, fs->epoch %d\n", kvs->data->pos, kvs->data->epoch);
//         // printk("Calling kvs_walk_unique\n");
//         // kvs_walk_unique(kvs, "", kvs_walk_cb, NULL);

//         // kvs_mount(kvs);

// }