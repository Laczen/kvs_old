<!--
  Copyright (c) 2022 Laczen

  SPDX-License-Identifier: Apache-2.0
-->
# KVS - key value store for embedded devices

Generic key value store interface to store and retrieve key-value entries on
different kind of memory devices e.g. RAM, FLASH (nor or nand), EEPROM, ...

## Introduction

KVS stores Key-value entries as:

```
  Entry header: the maximum length of the header is 13 bytes.
     byte 0: |. . .. .. ..|
              | | |  |  |-- value length bits 0-3: value length is 1-4 bytes
              | | |  |----- key length bits 0-3: key length is 1-4 bytes
              | | |------ unused
              | |-------- 1: includes wrap/erase counter, 0 no wrap counter
              |---------- odd parity bit (makes byte 0 odd parity)
     key length bytes
     value length bytes
     wrap counter (if included, 4 bytes)
   Entry data:
     key bytes (key length)
     value bytes (value length)
     fill bytes
   Entry footer:
     CRC32 value calculated over entry header and data (excluding fill).
```

 Entries are written sequentially to blocks that have a configurable size. At
 the beginning of each block a wrap counter is added to the entry. The wrap
 counter is increased each time the memory wraps around. When a new block is
 started the key value store verifies whether it needs to move old entries to
 keep a copy and does so if required.

 The configurable block size needs to be a power of 2. The block size limits
 the maximum size of an entry as it needs to fit within one block. The block
 size is not limited to an erase block size of the memory device, this allows
 using memory devices with non constant erase block sizes. However in this
 last case carefull parameter selection is required to guarantee that there
 will be no loss of data.

 ## documentation

 The API for KVS is documented in the header file [kvs.h](./lib/include/kvs.h).