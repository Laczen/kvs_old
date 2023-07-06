/*
 * Copyright (c) 2012-2014 Wind River Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/subsys/kvs.h>

LOG_MODULE_REGISTER(kvs_sample);

int main(void)
{
	struct kvs *kvs_store = GET_KVS(DT_NODELABEL(kvs_storage));
	int rc;
	int data;

	LOG_INF("KVS_SAMPLE");
	rc = kvs_mount(kvs_store);
	LOG_INF("kvs_mount [%s]", rc == 0 ? "OK" : "Failed");
	rc = kvs_unmount(kvs_store);
	LOG_INF("kvs_unmount [%s]", rc == 0 ? "OK" : "Failed");
	rc = kvs_erase(kvs_store);
	LOG_INF("kvs_erase [%s]", rc == 0 ? "OK" : "Failed");

	rc = kvs_mount(kvs_store);
	LOG_INF("kvs_mount [%s]", rc == 0 ? "OK" : "Failed");
	rc = kvs_write(kvs_store, "test", (void *)&rc, sizeof(rc));
	LOG_INF("kvs_write [%s]", rc == 0 ? "OK" : "Failed");
	rc = kvs_read(kvs_store, "test", (void *)&data, sizeof(data));
	LOG_INF("kvs_read [%s]", rc == 0 ? "OK" : "Failed");
	LOG_INF("data: %d", data);

	return 0;
}
