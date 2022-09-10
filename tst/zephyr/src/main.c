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

ZTEST(kvs_tests, a_kvs_mount)
{
        struct kvs *kvs = GET_KVS(test);
        int rc;

        (void)kvs_unmount(kvs);
        rc = kvs_mount(kvs);
        zassert_false(rc != 0, "mount failed [%d]", rc);
        rc = kvs_unmount(kvs);
        zassert_false(rc != 0, "unmount failed [%d]", rc);
}

ZTEST(kvs_tests, b_kvs_rw)
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

ZTEST(kvs_tests, c_kvs_remount)
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

int kvs_walk_unique_test_cb(const struct kvs_ent *ent, void *cb_arg)
{
        uint32_t *value = (uint32_t *)cb_arg;

        return kvs_entry_read(ent, ent->val_start, value, sizeof(uint32_t));
}

ZTEST(kvs_tests, d_kvs_walk)
{
        struct kvs *kvs = GET_KVS(test);
        uint32_t cnt, en_cnt;
        int rc;

        (void)kvs_unmount(kvs);
        rc = kvs_mount(kvs);
        zassert_false(rc != 0, "mount failed [%d]", rc);

        /*
         * write one entry "/wlk_tst", walk searching for "/wlk_tst" and
         * count appearances, this should be one
         */
        cnt = 0U;
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
         cnt++;
        rc = kvs_write(kvs, "/wlk_tst", &cnt, sizeof(cnt));
        zassert_false(rc != 0, "write failed [%d]", rc);
        en_cnt = 0U;
        rc = kvs_walk(kvs, "/wlk_tst", kvs_walk_test_cb, (void *)&en_cnt);
        zassert_false(rc != 0, "walk failed [%d]", rc);
        zassert_false(en_cnt != 2U, "wrong walk result value");

        /* walk_unique searching for "/wlk_tst" and get the value */
        rc = kvs_walk_unique(kvs, "/wlk_tst", kvs_walk_unique_test_cb,
                             (void *)&en_cnt);
        zassert_false(rc != 0, "walk failed [%d]", rc);
        zassert_false(en_cnt != cnt, "wrong walk result value");
}

ZTEST(kvs_tests, e_kvs_compact)
{
        struct kvs *kvs = GET_KVS(test);
        int rc;

        (void)kvs_unmount(kvs);
        rc = kvs_mount(kvs);
        zassert_false(rc != 0, "mount failed [%d]", rc);

        rc = kvs_compact(kvs);
        zassert_false(rc != 0, "compact failed [%d]", rc);
}

ZTEST(kvs_tests, f_kvs_gc)
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