#include <zephyr/kernel.h>
#include "zephyr/ztest.h"
#include <zephyr/logging/log.h>
#include <zephyr/subsys/kvs.h>

LOG_MODULE_REGISTER(kvs_test);

ZTEST_SUITE(kvs_tests, NULL, NULL, NULL, NULL, NULL);

ZTEST(kvs_tests, a_kvs_mount)
{
	struct kvs *kvs = GET_KVS(DT_NODELABEL(kvs_storage));
	int rc;

	(void)kvs_unmount(kvs);
	rc = kvs_erase(kvs);
	zassert_false(rc != 0, "erase failed [%d]", rc);
	rc = kvs_mount(kvs);
	zassert_false(rc != 0, "mount failed [%d]", rc);
	rc = kvs_unmount(kvs);
	zassert_false(rc != 0, "unmount failed [%d]", rc);
}

ZTEST(kvs_tests, b_kvs_rw)
{
	struct kvs *kvs = GET_KVS(DT_NODELABEL(kvs_storage));
	uint32_t cnt, cnt1, cn, rd_cnt;
	int rc;

	(void)kvs_unmount(kvs);
	rc = kvs_mount(kvs);
	zassert_false(rc != 0, "mount failed [%d]", rc);

	cnt = 0U;
	rc = kvs_write(kvs, "/cnt", &cnt, sizeof(cnt));
	zassert_false(rc != 0, "write failed [%d]", rc);

	rd_cnt = 255U;
	rc = kvs_read(kvs, "/cnt", &rd_cnt, sizeof(rd_cnt));
	zassert_false(rc != 0, "read failed [%d]", rc);
	zassert_false(rd_cnt != cnt, "wrong read value");

	cnt1 = 1U;
	rc = kvs_write(kvs, "/cnt1", &cnt1, sizeof(cnt1));
	zassert_false(rc != 0, "write failed [%d]", rc);

	rd_cnt = 255U;
	rc = kvs_read(kvs, "/cnt1", &rd_cnt, sizeof(rd_cnt));
	zassert_false(rc != 0, "read failed [%d]", rc);
	zassert_false(rd_cnt != cnt1, "wrong read value");

	cn = 2U;
	rc = kvs_write(kvs, "/cn", &cn, sizeof(cn));
	zassert_false(rc != 0, "write failed [%d]", rc);

	rd_cnt = 255U;
	rc = kvs_read(kvs, "/cn", &rd_cnt, sizeof(rd_cnt));
	zassert_false(rc != 0, "read failed [%d]", rc);
	zassert_false(rd_cnt != cn, "wrong read value");

	rd_cnt = 255U;
	rc = kvs_read(kvs, "/cnt", &rd_cnt, sizeof(rd_cnt));
	zassert_false(rc != 0, "read failed [%d]", rc);
	zassert_false(rd_cnt != cnt, "wrong read value");

	rd_cnt = 255U;
	rc = kvs_read(kvs, "/cnt1", &rd_cnt, sizeof(rd_cnt));
	zassert_false(rc != 0, "read failed [%d]", rc);
	zassert_false(rd_cnt != cnt1, "wrong read value");

	rc = kvs_unmount(kvs);
	zassert_true(rc == 0, "unmount failed [%d]", rc);
}

ZTEST(kvs_tests, c_kvs_remount)
{
	struct kvs *kvs = GET_KVS(DT_NODELABEL(kvs_storage));
	uint32_t cnt, pos, bend, wrapcnt;
	int rc;

	(void)kvs_unmount(kvs);
	rc = kvs_mount(kvs);
	zassert_false(rc != 0, "mount failed [%d]", rc);

	cnt = 0U;
	rc = kvs_write(kvs, "/cnt", &cnt, sizeof(cnt));
	zassert_false(rc != 0, "write failed [%d]", rc);

	pos = kvs->data->pos;
	bend = kvs->data->bend;
	wrapcnt = kvs->data->wrapcnt;

	rc = kvs_unmount(kvs);
	zassert_true(rc == 0, "unmount failed [%d]", rc);

	rc = kvs_mount(kvs);
	zassert_false(rc != 0, "mount failed [%d]", rc);
	zassert_false(pos != kvs->data->pos, "wrong kvs->data->pos");
	zassert_false(bend != kvs->data->bend, "wrong kvs->data->bend");
	zassert_false(wrapcnt != kvs->data->wrapcnt, "wrong kvs->data->wrapcnt");

	rc = kvs_unmount(kvs);
	zassert_true(rc == 0, "unmount failed [%d]", rc);
}

int kvs_walk_test_cb(struct kvs_ent *ent, void *cb_arg)
{
	uint32_t *cnt = (uint32_t *)cb_arg;

	(*cnt) += 1;
	return 0;
}

int kvs_walk_unique_test_cb(struct kvs_ent *ent, void *cb_arg)
{
	uint32_t *value = (uint32_t *)cb_arg;

	return kvs_entry_read(ent, ent->val_start, value, sizeof(uint32_t));
}

ZTEST(kvs_tests, d_kvs_walk)
{
	struct kvs *kvs = GET_KVS(DT_NODELABEL(kvs_storage));
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

	/* walk again searching for "/wlk" and count appearances, this should be
	 * one again.
	 */
	en_cnt = 0U;
	rc = kvs_walk(kvs, "/wlk", kvs_walk_test_cb, (void *)&en_cnt);
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
	struct kvs *kvs = GET_KVS(DT_NODELABEL(kvs_storage));
	uint32_t rd_cnt;
	int rc;

	(void)kvs_unmount(kvs);
	rc = kvs_mount(kvs);
	zassert_false(rc != 0, "mount failed [%d]", rc);
	LOG_INF("pos %d bend %d wrapcnt %d", kvs->data->pos, kvs->data->bend, kvs->data->wrapcnt);
	
	rc = kvs_compact(kvs);
	zassert_false(rc != 0, "compact failed [%d]", rc);
	LOG_INF("pos %d bend %d wrapcnt %d", kvs->data->pos, kvs->data->bend, kvs->data->wrapcnt);
	rc = kvs_read(kvs, "/cnt", &rd_cnt, sizeof(rd_cnt));
	zassert_false(rc != 0, "read failed [%d]", rc);

	rc = kvs_read(kvs, "/cnt1", &rd_cnt, sizeof(rd_cnt));
	zassert_false(rc != 0, "read failed [%d]", rc);

	rc = kvs_read(kvs, "/cn", &rd_cnt, sizeof(rd_cnt));
	zassert_false(rc != 0, "read failed [%d]", rc);

	rc = kvs_read(kvs, "/wlk_tst", &rd_cnt, sizeof(rd_cnt));
	zassert_false(rc != 0, "read failed [%d]", rc);

	rc = kvs_delete(kvs, "/wlk_tst");
	zassert_false(rc != 0, "delete failed [%d]", rc);

	rc = kvs_compact(kvs);
	zassert_false(rc != 0, "compact failed [%d]", rc);
	LOG_INF("pos %d bend %d wrapcnt %d", kvs->data->pos, kvs->data->bend, kvs->data->wrapcnt);

	rc = kvs_read(kvs, "/cnt", &rd_cnt, sizeof(rd_cnt));
	zassert_false(rc != 0, "read failed [%d]", rc);

	rc = kvs_read(kvs, "/cnt1", &rd_cnt, sizeof(rd_cnt));
	zassert_false(rc != 0, "read failed [%d]", rc);

	rc = kvs_read(kvs, "/cn", &rd_cnt, sizeof(rd_cnt));
	zassert_false(rc != 0, "read failed [%d]", rc);

	rc = kvs_read(kvs, "/wlk_tst", &rd_cnt, sizeof(rd_cnt));
	zassert_false(rc == 0, "read succeeded on deleted item [%d]", rc);

	rc = kvs_compact(kvs);
	zassert_false(rc != 0, "compact failed [%d]", rc);
	LOG_INF("pos %d bend %d wrapcnt %d", kvs->data->pos, kvs->data->bend, kvs->data->wrapcnt);

	rc = kvs_read(kvs, "/cnt", &rd_cnt, sizeof(rd_cnt));
	zassert_false(rc != 0, "read failed [%d]", rc);

	rc = kvs_read(kvs, "/cnt1", &rd_cnt, sizeof(rd_cnt));
	zassert_false(rc != 0, "read failed [%d]", rc);

	rc = kvs_read(kvs, "/cn", &rd_cnt, sizeof(rd_cnt));
	zassert_false(rc != 0, "read failed [%d]", rc);

	rc = kvs_read(kvs, "/wlk_tst", &rd_cnt, sizeof(rd_cnt));
	zassert_false(rc == 0, "read succeeded on deleted item [%d]", rc);
}

ZTEST(kvs_tests, f_kvs_gc)
{
	struct kvs *kvs = GET_KVS(DT_NODELABEL(kvs_storage));
	uint32_t cnt, wrapcnt;
	int rc;

	(void)kvs_unmount(kvs);
	rc = kvs_erase(kvs);
	zassert_false(rc != 0, "erase failed [%d]", rc);
	rc = kvs_mount(kvs);
	zassert_false(rc != 0, "mount failed [%d]", rc);

	cnt = 0U;
	rc = kvs_write(kvs, "c", &cnt, sizeof(cnt));
	zassert_false(rc != 0, "write failed [%d]", rc);
	wrapcnt = kvs->data->wrapcnt;

	while (kvs->data->wrapcnt == wrapcnt) {
		cnt++;
		rc = kvs_write(kvs, "ccccc", &cnt, sizeof(cnt));
		zassert_false(rc != 0, "write failed [%d]", rc);
		LOG_INF("pos %d", kvs->data->pos);
	}

	LOG_INF("NXT pos %d", kvs->data->pos);
	rc = kvs_read(kvs, "c", &cnt, sizeof(cnt));
	zassert_false(rc != 0, "read failed [%d]", rc);
	zassert_false(cnt != 0U, "wrong read value %d", cnt);

	rc = kvs_read(kvs, "ccccc", &cnt, sizeof(cnt));
	zassert_false(rc != 0, "read failed [%d]", rc);
	
	rc = kvs_delete(kvs, "c");
	zassert_false(rc != 0, "delete failed [%d]", rc);

	rc = kvs_read(kvs, "c", &cnt, sizeof(cnt));
	zassert_false(rc == 0, "read succeeded on deleted item");

	wrapcnt = kvs->data->wrapcnt;

	while (kvs->data->wrapcnt == wrapcnt) {
		cnt++;
		rc = kvs_write(kvs, "ccccc", &cnt, sizeof(cnt));
		zassert_false(rc != 0, "write failed [%d]", rc);
	}

	rc = kvs_read(kvs, "c", &cnt, sizeof(cnt));
	zassert_false(rc == 0, "read succeeded on deleted item");

	rc = kvs_read(kvs, "ccccc", &cnt, sizeof(cnt));
	zassert_false(rc != 0, "read failed [%d]", rc);

	rc = kvs_unmount(kvs);
	zassert_true(rc == 0, "unmount failed [%d]", rc);
}

// ZTEST(kvs_tests, g_kvs_erase)
// {
// 	struct kvs *kvs = GET_KVS(DT_NODELABEL(kvs_storage));
// 	uint32_t en_cnt = 0U;
// 	int rc;

// 	(void)kvs_unmount(kvs);
// 	rc = kvs_erase(kvs);
// 	zassert_false(rc != 0, "erase failed [%d]", rc);
// 	rc = kvs_mount(kvs);
// 	zassert_false(rc != 0, "mount failed [%d]", rc);
// 	zassert_false(kvs->data->pos != 0U, "wrong kvs->data->pos [%x]", kvs->data->pos);
// 	zassert_false(kvs->data->wrapcnt != 0U, "wrong kvs->data->wrapcnt");
// 	rc = kvs_walk(kvs, "", kvs_walk_test_cb, (void *)&en_cnt);
// 	zassert_false(rc != 0, "walk failed [%d]", rc);
// 	zassert_false(en_cnt != 0U, "found data on erased kvs");
// 	rc = kvs_unmount(kvs);
// 	zassert_true(rc == 0, "unmount failed [%d]", rc);
// }