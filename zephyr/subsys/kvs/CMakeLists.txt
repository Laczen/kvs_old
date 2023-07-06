# SPDX-License-Identifier: Apache-2.0

zephyr_sources_ifdef(CONFIG_KVS_BACKEND_FLASH kvs_backend_flash.c)
zephyr_sources_ifdef(CONFIG_KVS_BACKEND_EEPROM kvs_backend_eeprom.c)