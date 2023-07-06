#include <zephyr/kernel.h>
#include "kvs/kvs.h"

#define KVS_FLASH_EXT_DEFINE(inst)                                              \
        extern struct kvs inst;

DT_FOREACH_STATUS_OKAY(zephyr_kvs_flash, KVS_FLASH_EXT_DEFINE)
