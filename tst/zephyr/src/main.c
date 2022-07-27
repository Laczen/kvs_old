#include <stdarg.h>
#include <zephyr.h>
#include <ztest.h>
#include <sys/printk.h>
#include "kvs/kvs.h"


uint8_t back[1280];
uint8_t pbuf[8];

static int read(void *ctx, uint32_t offset, void *data, uint32_t len)
{
        uint8_t *data8 = (uint8_t *)data;

        if ((offset + len) > sizeof(back)) {
                return -1;
        }

        memcpy(data8, &back[offset], len);
        return 0;
}

static int prog(void *ctx, uint32_t offset, const void *data, uint32_t len)
{
        const uint8_t *data8 = (uint8_t *)data;

        if ((offset + len) > sizeof(back)) {
                return -1;
        }

        if (offset % 256 == 0) {
                memset(&back[offset], 0, 256);
        }

        memcpy(&back[offset], data8, len);
        return 0;
}

static int comp(void *ctx, uint32_t offset, const void *data, uint32_t len)
{
        const uint8_t *data8 = (uint8_t *)data;

        if (memcmp(&back[offset], data8, len) != 0) {
                return -KVS_EIO;
        }

        return 0;
}


static bool is_writable(void *ctx, uint32_t offset, uint32_t len)
{
        uint8_t buf[len];

        memset(buf, 0, len);
        return comp(ctx, offset, buf, len);
}

#define HASH_TABLE_ENTRIES 32
uint8_t hash_table[HASH_TABLE_ENTRIES];

static uint32_t hash(const void *key, uint32_t len, uint32_t sv)
{
    uint8_t *p = (uint8_t *)key;
    
    while (len-- != 0) { 
        sv = 31 * sv + (*p++);
    }
    
    return sv;
}

static uint32_t hash_get_block_addr(uint32_t hash)
{
        return hash_table[hash % HASH_TABLE_ENTRIES];
}

static void hash_set_block_addr(uint32_t hash, uint32_t addr)
{
        hash_table[hash % HASH_TABLE_ENTRIES] = (uint8_t)addr;
}

static void hash_init_block_addr(uint32_t addr)
{
        for (int i = 0; i < HASH_TABLE_ENTRIES; i++) {
                hash_table[i] = (uint8_t)addr;
        }
}

const struct kvs_fs_cfg fs_cfg = {
        .ctx = NULL,
        .pbuf = (void *)&pbuf,
        .psize = 4,
        .read = read,
        .prog = prog,
        .comp = comp,
        .sync = NULL,
        .is_writable = is_writable,
        .lock = NULL,
        .unlock = NULL,
        .hash = hash,
        .hash_get_block_addr = hash_get_block_addr,
        .hash_set_block_addr = hash_set_block_addr,
        .hash_init_block_addr = hash_init_block_addr,
};

struct kvs_fs fs = {
        .cfg = &fs_cfg,
        .bsize = 256,
        .bcnt = 5,
        .bspr = 1,
        .pos = 0,
        .bend = 256,
};

int kvs_walk_cb(const struct kvs_ent *ent)
{
        char buf[12];
        kvs_entry_read(ent, ent->key_start, buf, KVS_MIN(12, ent->val_start - ent->key_start));
        buf[ent->val_start-ent->key_start]= '\0';
        printk("Found entry at %d named %s\n", ent->start, buf);
        return 0;
}

void test_main(void)
{
        int rc;
        struct kvs_ent entry;

        kvs_init_hash_table(&fs);

        printk("Testing\n");
        uint8_t cnt = 96;
        while ((fs.epoch == 0) && (--cnt > 0U)) {
                rc = kvs_entry_add(&entry, &fs, "testkep", 234);
                if (rc == -KVS_ENOSPC) {
                        break;
                }
                
                kvs_entry_write(&entry, entry.val_start, &cnt, sizeof(cnt));                                
                kvs_entry_flush(&entry);
        }

        kvs_walk_unique(&fs, "t", kvs_walk_cb);

        printk("cnt: %d\n", cnt);
        rc = kvs_entry_add(&entry, &fs, "testkey", 1);
        kvs_entry_write(&entry, entry.val_start, &cnt, sizeof(cnt));
        rc = kvs_entry_flush(&entry);

        printk("%d %d %d %d %d\n", entry.start, entry.key_start, entry.val_start, entry.val_len, entry.next);

        for (int i= 0; i < entry.ext_start; i++) {
                printk("%x ", back[i + entry.start]);
        }

        for (int i = entry.ext_start; i < entry.key_start; i++) {
                printk("%c", back[i + entry.start]);
        }

        printk(" ");

        for (int i = entry.key_start; i < entry.val_start; i++) {
                printk("%c", back[i + entry.start]);
        }

        printk(" ");
        
        for (int i = entry.val_start; i < (entry.next - entry.start); i++) {
                printk("%x", back[i + entry.start]);
        }

        printk("\n");

        char tstdata[] = "datatst";
        rc = kvs_entry_add(&entry, &fs, "testit", 12);
        rc = kvs_entry_write(&entry, entry.val_start,
                             tstdata, sizeof(tstdata));
        rc = kvs_entry_flush(&entry);
        printk("%d %d %d %d %d\n", entry.start, entry.key_start, entry.val_start, entry.val_len, entry.next);

        memcpy(tstdata, "dayatst", 7);

        rc = kvs_entry_add(&entry, &fs, "testit", 7);
        rc = kvs_entry_write(&entry, entry.val_start,
                             tstdata, sizeof(tstdata));
        rc = kvs_entry_flush(&entry);
        printk("%d %d %d %d %d\n", entry.start, entry.key_start, entry.val_start, entry.val_len, entry.next);

        printk("Doing read\n");
        char rddata[sizeof(tstdata)];
        rc = kvs_read(&fs, "testit", rddata, sizeof(tstdata));
        printk("Read result: %d data %s\n", rc, rddata);

        uint8_t tst;
        rc = kvs_read(&fs, "testkey", &tst, sizeof(tst));
        printk("Read result: %d %x\n", rc, tst);

        rc = kvs_read(&fs, "test", &tst, sizeof(tst));
        printk("Read result: %d %x\n", rc, tst);

        rc = kvs_read(&fs, "testkep", &rddata, sizeof(tstdata));
        printk("Read result: %d %s\n", rc, rddata);

        printk("htable: ");
        for (int i = 0; i < HASH_TABLE_ENTRIES; i++) {
                printk("%x ", hash_table[i]);
        }
        printk("\n");

        printk("Testing gc\n");
        for (int i = 0; i < 96; i++) {
                rc = kvs_entry_add(&entry, &fs, "testit1", 12);
                rc = kvs_entry_write(&entry, entry.val_start,
                             tstdata, sizeof(tstdata));
                rc = kvs_entry_flush(&entry);
        }
        printk("Calling kvs_walk\n");
        kvs_walk(&fs, "", kvs_walk_cb);

        printk("Calling kvs_walk_unique\n");
        kvs_walk_unique(&fs, "", kvs_walk_cb);
        printk("Calling kvs_walk_unique\n");
        kvs_walk_unique(&fs, "testit", kvs_walk_cb);
        printk("Calling compact...\n");
        kvs_compact(&fs);
        printk("Calling kvs_walk_unique\n");
        kvs_walk_unique(&fs, "", kvs_walk_cb);

}