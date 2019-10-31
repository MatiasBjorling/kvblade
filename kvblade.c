/* Copyright (C) 2006 Coraid, Inc.  See COPYING for GPL terms. */
/* Copyright (C) 2019 John Sharratt.  See COPYING for GPL terms. */

#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/netdevice.h>
#include <linux/kthread.h>
#include <linux/ata.h>
#include <linux/ctype.h>
#include <uapi/linux/hdreg.h>

#include "aoe.h"

#define AOE_DEBUG
//#define AOE_DEBUG_VERBOSE

#define xprintk(L, fmt, arg...) printk(L "kvblade: " "%s: " fmt, __func__, ## arg)
#define iprintk(fmt, arg...) xprintk(KERN_INFO, fmt, ## arg)
#define eprintk(fmt, arg...) xprintk(KERN_ERR, fmt, ## arg)
#define wprintk(fmt, arg...) xprintk(KERN_WARN, fmt, ## arg)
#define dprintk(fmt, arg...) if(0);else xprintk(KERN_DEBUG, fmt, ## arg)

#ifdef AOE_DEBUG
#define tiprintk(fmt, arg...) printk(KERN_INFO fmt, ## arg)
#define teprintk(fmt, arg...) printk(KERN_ERR fmt, ## arg)
#define twprintk(fmt, arg...) printk(KERN_WARN fmt, ## arg)
#else
#define tiprintk(fmt, arg...) trace_printk(KERN_INFO fmt, ## arg)
#define teprintk(fmt, arg...) trace_printk(KERN_ERR fmt, ## arg)
#define wtprintk(fmt, arg...) trace_printk(KERN_WARN fmt, ## arg)
#endif

#define nelem(A) (sizeof (A) / sizeof (A)[0])

#define MAXSECTORS(mtu) (((mtu) - sizeof (struct aoe_hdr) - sizeof (struct aoe_atahdr)) / 512)
#define MAXBUFFERS  1024
#define MAXIOVECS 16
#define HEADERSIZE sizeof(struct aoe_hdr) + sizeof(struct aoe_cfghdr)

#define bio_sector(bio) ((bio)->bi_iter.bi_sector)
#define bio_size(bio) ((bio)->bi_iter.bi_size)
#define bio_idx(bio) ((bio)->bi_iter.bi_idx)

#ifndef KERNEL_SECTOR_SIZE
#define KERNEL_SECTOR_SIZE 512
#endif

enum {
    ATA_MODEL_LEN = 40,
    ATA_LBA28MAX = 0x0fffffff,
};

enum
{
    AOEERR_CMD= 1,
    AOEERR_ARG,
    AOEERR_DEV,
    AOEERR_CFG,
    AOEERR_VER,
};

struct aoetarget;

struct aoereq {
    struct sk_buff *skb;    // Reference to the packet that initiated the request
    struct aoetarget *d;       // Reference to the device that the request will be actioned on
    struct aoethread* t;    // Reference to the thread thats processing this command
    int err;
    
    struct bio bio;         // The BIO structure is cached in the AOE request to minimize the calls to memory allocation
    struct bio_vec bvl[MAXIOVECS];  // These must be placed together as the BIO implementation requires it
    
} ____cacheline_aligned_in_smp typedef aoereq_t;

struct aoetarget_thread {
    atomic_t                busy;    
} ____cacheline_aligned_in_smp typedef aoetarget_thread_t;

struct aoetarget {
    
    // This next 64 bytes are aligned and packed together so that
    // the driver keeps a single cache line hot per device
    struct hlist_node       node;
    __be16                  major;
    __be16                  minor;
    
    struct net_device*      netdev;
    struct block_device*    blkdev;
    
    struct aoetarget_thread*   devthread_percpu;
    
    struct kobject          kobj;
    
    int                     nconfig;
    loff_t                  scnt;
    
    
    unsigned char           config[1024];   

    char                    path[256];
    
    char                    model[ATA_MODEL_LEN];
    char                    sn[ATA_ID_SERNO_LEN];
    
    struct rcu_head         rcu; // List head used to delay the release of this object till after RCU sync
    
} ____cacheline_aligned_in_smp typedef aoetarget_t;

struct kvblade_sysfs_entry {
    struct attribute attr;
    ssize_t(*show)(struct aoetarget *, char *);
    ssize_t(*store)(struct aoetarget *, const char *, size_t);
};

struct aoethread {

    struct sk_buff_head skb_outq;
    struct sk_buff_head skb_inq;
    struct sk_buff_head skb_com;
    atomic_t            announce_all;
    
    struct completion   ktrendez;
    struct task_struct* task;
    
} ____cacheline_aligned_in_smp typedef aoethread_t;

struct core
{
    spinlock_t          lock;
    struct hlist_head   devlist;
    struct kmem_cache*  aoe_rq_cache;
    struct kobject      kvblade_kobj;
    
    struct aoethread*   thread_percpu;
    
} ____cacheline_aligned_in_smp typedef core_t;

static core_t root;

static struct kobj_type kvblade_ktype;

static void kvblade_release(struct kobject *kobj) {
}

static ssize_t kvblade_get_capacity(struct block_device *bd) {
    if (bd->bd_part != NULL)
        return bd->bd_part->nr_sects;
    return get_capacity(bd->bd_disk);
}

static ssize_t kvblade_sysfs_args(char *p, char *argv[], int argv_max) {
    int argc = 0;

    while (*p) {
        while (*p && isspace(*p))
            ++p;
        if (*p == '\0')
            break;
        if (argc < argv_max)
            argv[argc++] = p;
        else {
            teprintk("kvblade: too many args!\n");
            return -1;
        }
        while (*p && !isspace(*p))
            ++p;
        if (*p)
            *p++ = '\0';
    }
    return argc;
}

static struct sk_buff * skb_new(struct aoethread* t, struct net_device *dev, ulong len) {
    struct sk_buff *skb;

    if (len < ETH_ZLEN)
        len = ETH_ZLEN;

    skb = __alloc_skb(len, GFP_ATOMIC, SKB_ALLOC_FCLONE, numa_node_id());
    if (!skb)
        skb = __alloc_skb(len, GFP_ATOMIC & ~__GFP_DMA, 0, NUMA_NO_NODE);
    if (skb) {
        skb_reserve(skb, HEADERSIZE);
        skb_reset_network_header(skb);
        skb_reset_mac_header(skb);
        skb->dev = dev;
        skb->protocol = __constant_htons(ETH_P_AOE);
        skb->priority = 0;
        skb->next = skb->prev = NULL;
        skb->ip_summed = CHECKSUM_NONE;
        skb_put(skb, len);
    }
    return skb;
}

static char* spncpy(char *d, const char *s, int n) {
    char *r = d;

    memset(d, ' ', n);
    while (n-- > 0) {
        if (*s == '\0')
            break;
        *d++ = *s++;
    }
    return r;
}

static int count_busy(struct aoetarget *d) {
    int n;
    struct aoetarget_thread* dt;
    
    int ret =0;
    for (n = 0; n < num_online_cpus(); n++) {
        dt = (struct aoetarget_thread*)per_cpu_ptr(d->devthread_percpu, n);
        ret += atomic_read(&dt->busy);
    }
    return ret;
}

static void wake(struct aoethread* t)
{
    wake_up_process(t->task);
}

static int ata_maxsectors(struct aoetarget *d) {
    int ret = MAXSECTORS(d->netdev->mtu);
    if (ret > 64)
        ret = 64;
    else if (ret > 32)
        ret = 32;
    else if (ret > 16)
        ret = 16;
    else if (ret > 8)
        ret = 8;
    return ret;
}

static void announce(struct aoetarget *d, struct aoethread* t) {
    struct sk_buff* skb;
    struct aoe_hdr *aoe;
    struct aoe_cfghdr *cfg;
    int len = HEADERSIZE + d->nconfig;
    
    skb = skb_new(t, d->netdev, len);
    if (skb == NULL)
        return;
    
    aoe = (struct aoe_hdr *) skb_mac_header(skb);
    cfg = (struct aoe_cfghdr *)(aoe+1);

    memset(aoe, 0, sizeof *aoe);
    memcpy(aoe->src, d->netdev->dev_addr, ETH_ALEN);
    memset(aoe->dst, 0xFF, ETH_ALEN);

    aoe->type = __constant_htons(ETH_P_AOE);
    aoe->verfl = AOE_HVER | AOEFL_RSP;
    aoe->major = cpu_to_be16(d->major);
    aoe->minor = d->minor;
    aoe->cmd = AOECMD_CFG;

    memset(cfg, 0, sizeof *cfg);
    cfg->bufcnt = cpu_to_be16(MAXBUFFERS);
    cfg->fwver = __constant_htons(0x0002);
    cfg->scnt = ata_maxsectors(d);
    cfg->aoeccmd = AOE_HVER;

    if (d->nconfig) {
        *((__be16*)&cfg->cslen[0]) = cpu_to_be16(d->nconfig);
        memcpy((cfg+1), d->config, d->nconfig);
    }
    
#ifdef AOE_DEBUG_VERBOSE
    tiprintk("kvblade: sending announce for %04X.%02X\n", aoe->major, aoe->minor);    
#endif
    skb_queue_tail(&t->skb_outq, skb);
    wake(t);
}

static ssize_t kvblade_add(u32 major, u32 minor, char *ifname, char *path) {
    struct net_device *nd;
    struct net* ns;
    struct block_device *bd;
    struct aoetarget *d, *td;
    int ret = 0;
    struct aoethread* t;
    int n;
    struct aoetarget_thread* dt;
    
    tiprintk("kvblade: kvblade_add %04X.%02X\n", major, minor);
    nd = dev_get_by_name(&init_net, ifname);
    if (nd == NULL) {
        rcu_read_lock();
        for_each_net_rcu(ns) {
            nd = dev_get_by_name_rcu(ns, ifname);
            if (nd != NULL) break;
        }
        rcu_read_unlock();
        if (nd == NULL) {
            teprintk("kvblade: add failed: interface %s not found.\n", ifname);
            return -ENOENT;
        }
    }
    dev_put(nd);

    bd = blkdev_get_by_path(path, FMODE_READ | FMODE_WRITE, NULL);
    if (!bd || IS_ERR(bd)) {
        teprintk("kvblade: add failed: can't open block device %s: %ld\n", path, PTR_ERR(bd));
        return -ENOENT;
    }

    if (kvblade_get_capacity(bd) == 0) {
        teprintk("kvblade: add failed: zero sized block device.\n");
        ret = -ENOENT;
        goto err;
    }

    spin_lock(&root.lock);
    
    rcu_read_lock();
    hlist_for_each_entry_rcu_notrace(td, &root.devlist, node)
    {
        if (td->major == major &&
            td->minor == minor &&
            td->netdev == nd)
        {
            rcu_read_unlock();
            spin_unlock(&root.lock);

            teprintk("kvblade: add failed: device %d.%d already exists on %s.\n", major, minor, ifname);
            ret = -EEXIST;
            goto err;
        }
    }
    rcu_read_unlock();
    
    d = kmalloc(sizeof (struct aoetarget), GFP_KERNEL);
    if (!d) {
        spin_unlock(&root.lock);
        
        teprintk("kvblade: add failed: kmalloc error for %d.%d\n", major, minor);
        ret = -ENOMEM;
        goto err;
    }

    memset(d, 0, sizeof (struct aoetarget));
    INIT_HLIST_NODE(&d->node);
    d->blkdev = bd;
    d->netdev = nd;
    d->major = major;
    d->minor = minor;
    d->scnt = kvblade_get_capacity(bd);
    strncpy(d->path, path, nelem(d->path) - 1);
    spncpy(d->model, "EtherDrive(R) kvblade", nelem(d->model));
    spncpy(d->sn, "SN HERE", nelem(d->sn));
    
    d->devthread_percpu = (struct aoetarget_thread*)alloc_percpu(struct aoetarget_thread);
    if (!d->devthread_percpu) {
        spin_unlock(&root.lock);
        kfree(d);
        
        teprintk("kvblade: add failed: alloc_percpu error for %d.%d\n", major, minor);
        ret = -ENOMEM;
        goto err;
    }
    
    for (n = 0; n < num_online_cpus(); n++) {
        dt = (struct aoetarget_thread*)per_cpu_ptr(d->devthread_percpu, n);
        memset(dt, 0, sizeof(struct aoetarget_thread));
    }

    ret = kobject_init_and_add(&d->kobj, &kvblade_ktype, &root.kvblade_kobj, "%d.%d@%s", major, minor, ifname);
    if (ret) {
        spin_unlock(&root.lock);
        kfree(d);
        
        teprintk("kvblade: add failed: kobject_init_and_add error for %d.%d\n", major, minor);
        goto err;
    }

    hlist_add_head_rcu(&d->node, &root.devlist);
    spin_unlock(&root.lock);

    tiprintk("kvblade: added %s as %d.%d@%s: %Lu sectors.\n", path, major, minor, ifname, d->scnt);

    t = (struct aoethread*)per_cpu_ptr(root.thread_percpu, get_cpu());
    atomic_set(&t->announce_all, 1);
    wake(t);
    put_cpu();
    
    return 0;
err:
    blkdev_put(bd, FMODE_READ | FMODE_WRITE);
    return ret;
}

static ssize_t kvblade_readd(u32 major, u32 minor, char *ifname, char *path) {
    struct aoetarget *d, *td;
    struct block_device *obd = NULL; 
    struct block_device *bd = NULL; 
    int ret = 0;
    
    bd = blkdev_get_by_path(path, FMODE_READ | FMODE_WRITE, NULL);
    if (!bd || IS_ERR(bd)) {
        teprintk("kvblade: readd failed: can't open block device %s: %ld\n", path, PTR_ERR(bd));
        return -ENOENT;
    }
    
    spin_lock(&root.lock);
    
    d = NULL;
    rcu_read_lock();
    hlist_for_each_entry_rcu_notrace(td, &root.devlist, node) {
        if (td->major == major &&
            td->minor == minor &&
            strcmp(td->netdev->name, ifname) == 0)
        {
            d = td;
            break;
        }
    }
    
    if (d == NULL) {
        rcu_read_unlock();
        spin_unlock(&root.lock);
        
        ret = -ENOENT;
        goto out;
    }
    
    // Replace the block device reference and release the old one
    obd = d->blkdev;
    d->blkdev = bd;
    bd = NULL;
    
    // We are finished (fall through and exit)
    rcu_read_unlock();
    spin_unlock(&root.lock);
out:
    if (bd != NULL) {
        blkdev_put(bd, FMODE_READ | FMODE_WRITE);
        bd = NULL;
    }
    if (obd != NULL) {
        blkdev_put(obd, FMODE_READ | FMODE_WRITE);
        obd = NULL;
    }
    return ret;
}

void kvblade_del_rcu(struct rcu_head* head) {
    struct aoetarget *d = container_of(head, aoetarget_t, rcu);
    
    blkdev_put(d->blkdev, FMODE_READ | FMODE_WRITE);

    kobject_del(&d->kobj);
    kobject_put(&d->kobj);
    
    if (d->devthread_percpu != NULL) {
        free_percpu(d->devthread_percpu);
        d->devthread_percpu = NULL;
    }
}

static ssize_t kvblade_del(u32 major, u32 minor, char *ifname) {
    struct aoetarget *d;
    int ret;

    spin_lock(&root.lock);
    
    rcu_read_lock();
    hlist_for_each_entry_rcu_notrace(d, &root.devlist, node) {
        if (d->major == major &&
            d->minor == minor &&
            strcmp(d->netdev->name, ifname) == 0)
        {
            break;
        }
    }
    
    if (d == NULL) {
        rcu_read_unlock();
        
        teprintk("kvblade: del failed: device %d.%d@%s not found.\n", major, minor, ifname);
        ret = -ENOENT;
        goto err;
    } else if (count_busy(d)) {
        rcu_read_unlock();
        
        teprintk("kvblade: del failed: device %d.%d@%s is busy.\n", major, minor, ifname);
        ret = -EBUSY;
        goto err;
    }
    hlist_del_rcu(&d->node);
    rcu_read_unlock();
    
    spin_unlock(&root.lock);

    call_rcu(&d->rcu, kvblade_del_rcu);
    return 0;
err:
    spin_unlock(&root.lock);
    return ret;
}

static ssize_t store_add(struct aoetarget *dev, const char *page, size_t len) {
    int error = 0;
    char *argv[16];
    char *p;

    p = kmalloc(len + 1, GFP_KERNEL);
    memcpy(p, page, len);
    p[len] = '\0';

    if (kvblade_sysfs_args(p, argv, nelem(argv)) != 4) {
        teprintk("kvblade: bad arg count for add\n");
        error = -EINVAL;
    } else {
        error = kvblade_add(simple_strtoul(argv[0], NULL, 0),
            simple_strtoul(argv[1], NULL, 0),
            argv[2], argv[3]);
    }

    kfree(p);
    return error ? error : len;
}

static struct kvblade_sysfs_entry kvblade_sysfs_add = __ATTR(add, 0644, NULL, store_add);

static ssize_t store_del(struct aoetarget *dev, const char *page, size_t len) {
    int error = 0;
    char *argv[16];
    char *p;

    p = kmalloc(len + 1, GFP_KERNEL);
    memcpy(p, page, len);
    p[len] = '\0';

    if (kvblade_sysfs_args(p, argv, nelem(argv)) != 3) {
        teprintk("kvblade: bad arg count for del\n");
        error = -EINVAL;
    } else {
        error = kvblade_del(simple_strtoul(argv[0], NULL, 0),
            simple_strtoul(argv[1], NULL, 0),
            argv[2]);
    }

    kfree(p);
    return error ? error : len;
}

static struct kvblade_sysfs_entry kvblade_sysfs_del = __ATTR(del, 0644, NULL, store_del);

static ssize_t store_readd(struct aoetarget *dev, const char *page, size_t len) {
    int error = 0;
    char *argv[16];
    char *p;

    p = kmalloc(len + 1, GFP_KERNEL);
    memcpy(p, page, len);
    p[len] = '\0';

    if (kvblade_sysfs_args(p, argv, nelem(argv)) != 4) {
        teprintk("kvblade: bad arg count for readd\n");
        error = -EINVAL;
    } else {
        error = kvblade_readd(simple_strtoul(argv[0], NULL, 0),
            simple_strtoul(argv[1], NULL, 0),
            argv[2], argv[3]);
    }

    kfree(p);
    return error ? error : len;
}

static struct kvblade_sysfs_entry kvblade_sysfs_readd = __ATTR(readd, 0644, NULL, store_readd);

static ssize_t store_announce(struct aoetarget *dev, const char *page, size_t len) {
    int error = 0;
    struct aoethread* t;

    t = (struct aoethread*)per_cpu_ptr(root.thread_percpu, get_cpu());
    atomic_set(&t->announce_all, 1);
    wake(t);
    put_cpu();
    
    return error ? error : len;
}

static struct kvblade_sysfs_entry kvblade_sysfs_announce = __ATTR(announce, 0644, NULL, store_announce);

static ssize_t show_scnt(struct aoetarget *dev, char *page) {
    return sprintf(page, "%Ld\n", dev->scnt);
}

static struct kvblade_sysfs_entry kvblade_sysfs_scnt = __ATTR(scst, 0644, show_scnt, NULL);

static ssize_t show_busy(struct aoetarget *dev, char *page) {
    return sprintf(page, "%d\n", count_busy(dev));
}

static struct kvblade_sysfs_entry kvblade_sysfs_busy = __ATTR(busy, 0644, show_busy, NULL);

static ssize_t show_bdev(struct aoetarget *dev, char *page) {
    return print_dev_t(page, dev->blkdev->bd_dev);
}

static struct kvblade_sysfs_entry kvblade_sysfs_bdev = __ATTR(bdev, 0644, show_bdev, NULL);

static ssize_t show_bpath(struct aoetarget *dev, char *page) {
    return sprintf(page, "%.*s\n", (int) nelem(dev->path), dev->path);
}

static struct kvblade_sysfs_entry kvblade_sysfs_bpath = __ATTR(bpath, 0644, show_bpath, NULL);

static ssize_t show_model(struct aoetarget *dev, char *page) {
    return sprintf(page, "%.*s\n", (int) nelem(dev->model), dev->model);
}

static ssize_t store_model(struct aoetarget *dev, const char *page, size_t len) {
    spncpy(dev->model, page, nelem(dev->model));
    return 0;
}

static struct kvblade_sysfs_entry kvblade_sysfs_model = __ATTR(model, 0644, show_model, store_model);

static ssize_t show_sn(struct aoetarget *dev, char *page) {
    return sprintf(page, "%.*s\n", (int) nelem(dev->sn), dev->sn);
}

static ssize_t store_sn(struct aoetarget *dev, const char *page, size_t len) {
    spncpy(dev->sn, page, nelem(dev->sn));
    return 0;
}

static struct kvblade_sysfs_entry kvblade_sysfs_sn = __ATTR(sn, 0644, show_sn, store_sn);

static ssize_t show_mtu(struct aoetarget *dev, char *page) {
    return sprintf(page, "%d\n", (int)(ata_maxsectors(dev) * KERNEL_SECTOR_SIZE));
}

static struct kvblade_sysfs_entry kvblade_sysfs_mtu = __ATTR(mtu, 0644, show_mtu, NULL);

static struct attribute *kvblade_ktype_attrs[] = {
    &kvblade_sysfs_scnt.attr,
    &kvblade_sysfs_busy.attr,
    &kvblade_sysfs_bdev.attr,
    &kvblade_sysfs_bpath.attr,
    &kvblade_sysfs_model.attr,
    &kvblade_sysfs_sn.attr,
    &kvblade_sysfs_mtu.attr,
    NULL,
};

static struct attribute *kvblade_ktype_ops_attrs[] = {
    &kvblade_sysfs_add.attr,
    &kvblade_sysfs_del.attr,
    &kvblade_sysfs_readd.attr,
    &kvblade_sysfs_announce.attr,
    NULL,
};

static ssize_t kvblade_attr_show(struct kobject *kobj, struct attribute *attr, char *page) {
    struct kvblade_sysfs_entry *entry;
    struct aoetarget *dev;

    entry = container_of(attr, struct kvblade_sysfs_entry, attr);
    dev = container_of(kobj, struct aoetarget, kobj);

    if (!entry->show) {
        return -EIO;
    }

    return entry->show(dev, page);
}

static ssize_t kvblade_attr_store(struct kobject *kobj, struct attribute *attr,
        const char *page, size_t length) {
    ssize_t ret;
    struct kvblade_sysfs_entry *entry;

    entry = container_of(attr, struct kvblade_sysfs_entry, attr);

    if (kobj == &root.kvblade_kobj) {
        ret = entry->store(NULL, page, length);
    } else {
        struct aoetarget *dev = container_of(kobj, struct aoetarget, kobj);

        if (!entry->store)
            return -EIO;

        ret = entry->store(dev, page, length);
    }

    return ret;
}

static const struct sysfs_ops kvblade_sysfs_ops = {
    .show = kvblade_attr_show,
    .store = kvblade_attr_store,
};

static struct kobj_type kvblade_ktype = {
    .default_attrs = kvblade_ktype_attrs,
    .sysfs_ops = &kvblade_sysfs_ops,
    .release = kvblade_release,
};

static struct kobj_type kvblade_ktype_ops = {
    .default_attrs = kvblade_ktype_ops_attrs,
    .sysfs_ops = &kvblade_sysfs_ops,
    .release = kvblade_release,
};

static void setfld(u16 *a, int idx, int len, char *str) {
    u8 *p;

    for (p = (u8*) (a + idx); len; p += 2, len -= 2) {
        p[1] = *str ? *str++ : ' ';
        p[0] = *str ? *str++ : ' ';
    }
}

static int ata_identify(struct aoetarget *d, struct aoe_atahdr *ata) {
    char buf[64];
    u16 *words = (u16 *)(ata+1);
    u8 *cp;
    loff_t scnt;

    memset(words, 0, 512);

    words[47] = 0x8000;
    words[49] = 0x0200;
    words[50] = 0x4000;
    words[83] = 0x5400;
    words[84] = 0x4000;
    words[86] = 0x1400;
    words[87] = 0x4000;
    words[93] = 0x400b;

    sprintf(buf, "V%d.%d\n", 0, 2);
    setfld(words, 23, 8, buf);
    setfld(words, 27, nelem(d->model), d->model);
    setfld(words, 10, nelem(d->sn), d->sn);

    scnt = d->scnt;
    cp = (u8 *) & words[100];
    *cp++ = scnt;
    *cp++ = (scnt >>= 8);
    *cp++ = (scnt >>= 8);
    *cp++ = (scnt >>= 8);
    *cp++ = (scnt >>= 8);
    *cp++ = (scnt >>= 8);

    scnt = d->scnt;
    cp = (u8 *) & words[60];

    if (scnt & ~ATA_LBA28MAX)
        scnt = ATA_LBA28MAX;
    *cp++ = scnt;
    *cp++ = (scnt >>= 8);
    *cp++ = (scnt >>= 8);
    *cp++ = (scnt >>= 8) & 0xf;

    return 512;
}

static void skb_setlen(struct sk_buff* skb, int len)
{
    if (len > skb_headlen(skb)) {
        skb->data_len -= skb->len - len;
        skb->len       = len;
    } else {
        skb->len       = len;
        skb->data_len  = 0;
        skb_set_tail_pointer(skb, len);
    }
}

static void ktcom(struct aoethread* t, struct sk_buff *skb) {
    struct aoereq *rq, **prq;
    struct aoetarget *d;
    struct aoetarget_thread *dt;
    struct aoe_hdr *aoe;
    struct aoe_atahdr *ata;
    struct bio *bio;
    int len;
    unsigned int bytes;
    
    prq = (struct aoereq **)(&skb->cb[0]);
    rq = *prq;
    bio = &rq->bio;    
    d = rq->d;
    
    aoe = (struct aoe_hdr *) skb_mac_header(skb);
    ata = (struct aoe_atahdr *)(aoe+1);
    len = sizeof *aoe + sizeof *ata;
    
    if (!bio->bi_status) {
        bytes = ata->scnt * KERNEL_SECTOR_SIZE;        
        if (bio_data_dir(bio) == READ)
            len += bytes;
        
        ata->scnt = 0;
        ata->cmdstat = ATA_DRDY;
        ata->errfeat = 0;
        // should increment lba here, too
    } else {
        teprintk("kvblade: I/O error %d on %s (status=%d)\n", blk_status_to_errno(bio->bi_status), d->kobj.name, bio->bi_status);
        ata->cmdstat = ATA_ERR | ATA_DF;
        ata->errfeat = ATA_UNC | ATA_ABORTED;
    }

    dt = (struct aoetarget_thread*)per_cpu_ptr(d->devthread_percpu, get_cpu());
    atomic_dec(&dt->busy);
    put_cpu();
    
    skb_setlen(skb, len);    
    if (unlikely(!pskb_may_pull(skb, ETH_HLEN))) {
        dev_kfree_skb(skb);
        return;
    }
    
    dev_queue_xmit(skb);
    
    kmem_cache_free(root.aoe_rq_cache, rq);
}

static void ata_io_complete(struct bio *bio) {
    int    error = blk_status_to_errno(bio->bi_status);

    struct aoethread *t;
    struct aoetarget* d;
    struct aoereq *rq, **prq;
    struct sk_buff *skb;
    int cpu;
    
    rq = bio->bi_private;
    rq->err = error;
    skb = rq->skb;
    d = rq->d;
    
    prq = (struct aoereq **)(&skb->cb[0]);
    *prq = rq;
    
    cpu = get_cpu();
    t = (struct aoethread*)per_cpu_ptr(root.thread_percpu, cpu);
    rq->t = t;
    skb_queue_tail(&t->skb_com, skb);
    wake(t);
    put_cpu();
}

static inline loff_t readlba(u8 *lba) {
    loff_t n = 0ULL;
    int i;

    for (i = 5; i >= 0; i--) {
        n <<= 8;
        n |= lba[i];
    }
    return n;
}

static struct bio* rq_init_bio(struct aoereq *rq) {
    struct bio *bio;
    bio = &rq->bio;
    bio_init(bio, bio->bi_inline_vecs, MAXIOVECS);
    return bio;
}

static int skb_add_pages(struct sk_buff* skb, struct bio *bio, int len) {
    unsigned int offset = sizeof(struct aoe_hdr) + sizeof(struct aoe_atahdr);
    
    int sg_n, sg_i;
    int sg_max = skb_shinfo(skb)->nr_frags + 2;
    struct scatterlist sg_tbl[sg_max], *sgentry;
    
    // Validate that everything is ok
    if (offset + len > skb->len) {
        teprintk("kvblade: packet I/O is out of range: (%d), max %d\n", offset + len, skb->len);
        return 0;
    }
    
    // Create the source scatterlist from the received packet
    sg_init_table(sg_tbl, sg_max);
    sg_n = skb_to_sgvec(skb, sg_tbl, offset, len);
    if (sg_n <= 0) {
        return 0;
    }

    // Loop through all the scatterlist items and add them into the BIO
    for_each_sg(sg_tbl, sgentry, sg_n, sg_i) {
        if (bio_add_page(bio,
                         sg_page(sgentry),
                         sgentry->length,
                         sgentry->offset) < sgentry->length)
            return 0;
    }
    
    return len;
}

static struct sk_buff * rcv_ata(struct aoetarget *d, struct aoethread *t, struct sk_buff *skb) {
    struct aoe_hdr *aoe;
    struct aoe_atahdr *ata;
    struct aoereq *rq;
    struct aoetarget_thread *dt;
    struct bio *bio;
    sector_t lba;
    int len, rw;
    unsigned int data_len;
    
    aoe = (struct aoe_hdr *) skb_mac_header(skb);
    ata = (struct aoe_atahdr *)(aoe+1);
    lba = readlba(&ata->lba0);
    len = sizeof *aoe + sizeof *ata;
    data_len = ata->scnt * KERNEL_SECTOR_SIZE;
    
    switch (ata->cmdstat) {
        do {
            case ATA_CMD_PIO_READ:
                lba &= ATA_LBA28MAX;
            case ATA_CMD_PIO_READ_EXT:
                lba &= 0x0000FFFFFFFFFFFFULL;
                rw = READ;
                break;
            case ATA_CMD_PIO_WRITE:
                lba &= ATA_LBA28MAX;
            case ATA_CMD_PIO_WRITE_EXT:
                lba &= 0x0000FFFFFFFFFFFFULL;
                rw = WRITE;
        } while (0);
        
        // Default to error unless it is succesful
        ata->cmdstat = ATA_ERR;
        ata->errfeat = 0;

        // Do a check on the IO range
        if ((lba + ata->scnt) > d->scnt) {
            teprintk("kvblade: sector I/O is out of range: %Lu (%d), max %Lu\n", (long long) lba, ata->scnt, d->scnt);
            ata->errfeat = ATA_IDNF;
            break;
        }

        rq = (aoereq_t*) kmem_cache_alloc_node(root.aoe_rq_cache, GFP_ATOMIC & ~ __GFP_DMA, numa_node_id());
        if (unlikely(rq == NULL)) {
            rq = (aoereq_t*) kmem_cache_alloc_node(root.aoe_rq_cache, GFP_KERNEL, numa_node_id());
            if (unlikely(rq == NULL)) {
                teprintk("kvblade: failed to allocate ATA request memory\n");
                ata->errfeat = ATA_ABORTED;
                break;
            }
        }
        prefetchw(rq);

        bio = rq_init_bio(rq);
        prefetchw(bio);
        
        len += data_len;
        if (len > skb->len) {
            int delta = len - skb->len;
            
            if (skb->data_len > 0 ||
                skb->tail + delta > skb->end) {
                teprintk("kvblade: failed to expand SKB as it is non-linear or does not have enough space (len=%d skb->len=%d)\n", len, skb->len);
                ata->errfeat = ATA_ABORTED;
                break;
            }
            
            skb_put(skb, delta);
        }

        rq->d = d;
        rq->t = t;
        rq->skb = skb;

        bio_sector(bio) = lba;
        bio_set_dev(bio, d->blkdev);
        bio->bi_end_io = ata_io_complete;
        bio->bi_private = rq;

        if (skb_add_pages(skb, bio, data_len) <= 0) {
            kmem_cache_free(root.aoe_rq_cache, rq);
            teprintk("kvblade: can't bio_add_page for %d sectors\n", ata->scnt);
            goto drop;
        }

        dt = (struct aoetarget_thread*)per_cpu_ptr(d->devthread_percpu, get_cpu());
        atomic_inc(&dt->busy);
        put_cpu();

        if (rw == WRITE) {
            bio_set_op_attrs(bio, REQ_OP_WRITE, 0);
        } else {
            bio_set_op_attrs(bio, REQ_OP_READ, 0);
        }
        submit_bio(bio);
        return NULL;

    default:
        teprintk("kvblade: unknown ATA command 0x%02X\n", ata->cmdstat);
        ata->cmdstat = ATA_ERR;
        ata->errfeat = ATA_ABORTED;
        break;
    case ATA_CMD_ID_ATA:
#ifdef AOE_DEBUG_VERBOSE
        tiprintk("kvblade: received ATA_CMD_ID_ATA for %04X.%02X\n", aoe->major, aoe->minor);
#endif
        len += ata_identify(d, ata);
        // fall-through
    case ATA_CMD_FLUSH:
#ifdef AOE_DEBUG_VERBOSE
        tiprintk("kvblade: received ATA_CMD_FLUSH for %04X.%02X\n", aoe->major, aoe->minor);
#endif
        ata->cmdstat = ATA_DRDY;
        ata->errfeat = 0;
        break;
    }
    skb_trim(skb, len);
    return skb;
drop:
    dev_kfree_skb(skb);
    return NULL;
}

static struct sk_buff* rcv_cfg(struct aoetarget *d, struct aoethread *t, struct sk_buff *skb) {
    struct aoe_hdr *aoe;
    struct aoe_cfghdr *cfg;
    int len, cslen, ccmd;
    
    aoe = (struct aoe_hdr *) skb_mac_header(skb);
    cfg = (struct aoe_cfghdr *)(aoe+1);
    cslen = ntohs(*((__be16*)&cfg->cslen[0]));
    ccmd = cfg->aoeccmd & 0xf;
    len = sizeof *aoe;

    cfg->bufcnt = htons(MAXBUFFERS);
    cfg->scnt = ata_maxsectors(d);
    cfg->fwver = __constant_htons(0x0002);
    cfg->aoeccmd = AOE_HVER;

    if (cslen > nelem(d->config))
        goto drop;

    switch (ccmd) {
        case AOECCMD_TEST:
            tiprintk("kvblade: received AOECCMD_TEST for %04X.%02X\n", aoe->major, aoe->minor);
            if (d->nconfig != cslen)
                goto drop;
            // fall thru
        case AOECCMD_PTEST:
            tiprintk("kvblade: received AOECCMD_PTEST for %04X.%02X\n", aoe->major, aoe->minor);
            if (cslen > d->nconfig)
                goto drop;
            if (memcmp((cfg+1), d->config, cslen) != 0)
                goto drop;
            // fall thru
        case AOECCMD_READ:
            tiprintk("kvblade: received AOECCMD_READ for %04X.%02X\n", aoe->major, aoe->minor);
            *((__be16*)&cfg->cslen[0]) = cpu_to_be16(d->nconfig);
            memcpy((cfg+1), d->config, d->nconfig);
            len += sizeof *cfg + d->nconfig;
            break;
        case AOECCMD_SET:
            tiprintk("kvblade: received AOECCMD_SET for %04X.%02X\n", aoe->major, aoe->minor);
            if (d->nconfig)
                if (d->nconfig != cslen || memcmp((cfg+1), d->config, cslen) != 0) {
                    aoe->verfl |= AOEFL_ERR;
                    aoe->err = AOEERR_CFG;
                    break;
                }
            // fall thru
        case AOECCMD_FSET:
            tiprintk("kvblade: received AOECCMD_FSET for %04X.%02X\n", aoe->major, aoe->minor);
            d->nconfig = cslen;
            memcpy(d->config, (cfg+1), cslen);
            len += sizeof *cfg + cslen;
            break;
        default:
            teprintk("kvblade: unknown ATA CFG command 0x%02X for %04X.%02X\n", ccmd, aoe->major, aoe->minor);
            aoe->verfl |= AOEFL_ERR;
            aoe->err = AOEERR_ARG;
    }
    skb_trim(skb, len);
    return skb;
drop:
    dev_kfree_skb(skb);
    return NULL;
}

static void ktannounce(struct aoethread* t) {
    struct aoetarget *d;
    
    spin_lock(&root.lock);
    hlist_for_each_entry_rcu_notrace(d, &root.devlist, node)
    {
        announce(d, t);
    }
    spin_unlock(&root.lock);    
    return;
}

static struct sk_buff* conv_response(struct aoethread* t, struct sk_buff *skb, int major, int minor) {
    struct aoe_hdr *aoe;
    struct net_device* target = skb->dev;
    
    // Setup other parameters
    skb_scrub_packet(skb, false);
    skb->dev = target;

    // Set all the packet headers
    skb_reset_mac_header(skb);
    skb_reset_network_header(skb);
    skb_reset_transport_header(skb);
    skb_reset_mac_len(skb);

    aoe = (struct aoe_hdr *) skb_mac_header(skb);
    memcpy(aoe->dst, aoe->src, ETH_ALEN);
    memcpy(aoe->src, target->dev_addr, ETH_ALEN);
    aoe->type = __constant_htons(ETH_P_AOE);
    aoe->verfl = AOE_HVER | AOEFL_RSP;
    aoe->major = cpu_to_be16(major);
    aoe->minor = minor;
    aoe->err = 0;   
    return skb;
}

static struct sk_buff* clone_response(struct aoethread* t, struct sk_buff *skb, int major, int minor) {
    struct sk_buff *rskb;
    
    if (skb->len > skb->dev->mtu)
        return NULL;
    rskb = skb_new(t, skb->dev, skb->dev->mtu);
    if (rskb == NULL)
        return NULL;
    
    skb_copy_bits(skb, 0, skb_mac_header(rskb), skb->len);

    conv_response(t, rskb, major, minor);
    return rskb;
}

static void ktrcv(struct aoethread* t, struct sk_buff *skb, int cpu) {
    struct sk_buff *rskb = NULL;
    struct aoetarget *d;
    struct aoetarget_thread *dt;
    struct aoe_hdr* aoe;
    int major, minor;
    
    aoe = (struct aoe_hdr *) skb_mac_header(skb);
    major = be16_to_cpu(aoe->major);
    minor = aoe->minor;
    
    rcu_read_lock();
    if (~aoe->verfl & AOEFL_RSP)
    {
        hlist_for_each_entry_rcu_notrace(d, &root.devlist, node)
        {
            if ((major != d->major && major != 0xffff) ||
                    (minor != d->minor && minor != 0xff) ||
                    (skb->dev != d->netdev))
                continue;

            dt = (struct aoetarget_thread*)per_cpu_ptr(d->devthread_percpu, cpu);
            
            switch (aoe->cmd) {
                case AOECMD_ATA:
                {
                    struct aoe_atahdr *ata = (struct aoe_atahdr *)(aoe+1);
                    if (ata->cmdstat == ATA_CMD_PIO_WRITE ||
                        ata->cmdstat == ATA_CMD_PIO_WRITE_EXT)
                    {
                        if (skb->data_len > 0) {                            
                            rskb = conv_response(t, skb, d->major, d->minor);
                            if (rskb == NULL) goto out;
                            skb = NULL;
                        } else {
                            rskb = clone_response(t, skb, d->major, d->minor);
                            if (rskb == NULL) goto out;
                        }
                    }
                    else {
                        rskb = clone_response(t, skb, d->major, d->minor);
                        if (rskb == NULL) goto out;
                    }
                    
                    // Leave the lock (which means we must exit the loop)
                    atomic_inc(&dt->busy);
                    rcu_read_unlock();

                    // Process the IO (if an error occurs then they'll be
                    // a packet ready to send immediately)
                    rskb = rcv_ata(d, t, rskb);
                    if (rskb)
                        dev_queue_xmit(rskb);
                    
                    // Clean up and release the device
                    if (skb != NULL)
                        dev_kfree_skb(skb);
                    atomic_dec(&dt->busy);
                    return;
                }
                case AOECMD_CFG:
                {
                    rskb = clone_response(t, skb, d->major, d->minor);
                    if (rskb == NULL)
                        goto out;

                    rskb = rcv_cfg(d, t, rskb);
                    if (rskb)
                        dev_queue_xmit(rskb);
                    break;
                }
                default:
                    break;
            }

            // If its a specific address then we are finished
            if (major == d->major && minor == d->minor)
                break;
        }
    }

out:
    rcu_read_unlock();
    if (skb != NULL)
        dev_kfree_skb(skb);
}

static int rcv(struct sk_buff *skb, struct net_device *ndev, struct packet_type *pt, struct net_device *orig_dev) {
    struct aoethread* t;
    
    skb = skb_share_check(skb, GFP_ATOMIC);
    if (skb == NULL) {
        return -ENOMEM;
    }
    
    skb_push(skb, ETH_HLEN);
    if (unlikely(!pskb_may_pull(skb, sizeof(struct aoe_hdr) + sizeof(struct aoe_atahdr)))) {
        dev_kfree_skb(skb);
        return 0;
    }
    
    t = (struct aoethread*)per_cpu_ptr(root.thread_percpu, get_cpu());
    skb_queue_tail(&t->skb_inq, skb);
    wake(t);
    put_cpu();
    return 0;
}

static int kthread_work(struct aoethread* t, int cpu) {
    int ret = 0;
    struct sk_buff *iskb, *oskb, *cskb;
    
    do {
        if ((iskb = skb_dequeue(&t->skb_inq))) {
            ktrcv(t, iskb, cpu);
            ret = 1;
        }
        if ((cskb = skb_dequeue(&t->skb_com))) {
            ktcom(t, cskb);
            ret = 1;
        }
        if ((oskb = skb_dequeue(&t->skb_outq))) {
            dev_queue_xmit(oskb);
            ret = 1;
        }

    } while (iskb || cskb || oskb);
    
    if (atomic_xchg(&t->announce_all, 0) > 0) {
#ifdef AOE_DEBUG_VERBOSE
        tiprintk("kvblade: kvblade announce on cpu(%d)\n", smp_processor_id());
#endif
        ktannounce(t);
        ret = 1;
    }
    
    return ret;
}

static int kthread(void* data) {
    struct aoethread* t = (struct aoethread*)data;
    
    sigset_t blocked;
    int work;
    int cpu;
    
    skb_queue_head_init(&t->skb_outq);
    skb_queue_head_init(&t->skb_inq);
    skb_queue_head_init(&t->skb_com);

#ifdef PF_NOFREEZE
    current->flags |= PF_NOFREEZE;
#endif
    set_user_nice(current, -5);
    sigfillset(&blocked);
    sigprocmask(SIG_BLOCK, &blocked, NULL);
    flush_signals(current);
    complete(&t->ktrendez);
    
    tiprintk("kvblade: started a new kvblade thread (%d)\n", smp_processor_id());
    
    do {
        // When we are woken, the most important thing is to get straight
        // into working (this is on the critical latency path)
        cpu = get_cpu();
        work = kthread_work(t, cpu);
        put_cpu();
        
        // Enter a loop that processes work continuous until no work
        // is found up after a complete schedule
        set_current_state(TASK_RUNNING);
        for (; work == 1 && !kthread_should_stop();)
        {
            // Schedule
            schedule();
            
            // Now check for more work
            // (if none is found then we'll go into sleep mode)
            cpu = get_cpu();
            work = kthread_work(t, cpu);
            put_cpu();
        }
        
        // We have to process work after setting INTERRUPTIBLE or we risk missing a
        // wake up in between
        set_current_state(TASK_INTERRUPTIBLE);
        cpu = get_cpu();
        work = kthread_work(t, cpu);
        put_cpu();
        
        // If work was not found then we are good to go into a sleep operation
        // (which may be really short if the task is woker again via wake_up_process)
        if (work == 0 && !kthread_should_stop())
        {
            // Scheduling while in an INTERRUPTIBLE state will cause this
            // worker thread to go to sleep
            schedule();
        }
        
    } while (!kthread_should_stop());
    
    skb_queue_purge(&t->skb_outq);
    skb_queue_purge(&t->skb_inq);
    skb_queue_purge(&t->skb_com);
    
    tiprintk("kvblade: stopped a kvblade thread (%d)\n", smp_processor_id());
    
    __set_current_state(TASK_RUNNING);
    complete(&t->ktrendez);
    
    return 0;
}

static struct packet_type pt = {
    .type = __constant_htons(ETH_P_AOE),
    .func = rcv,
};

static int __init kvblade_module_init(void) {
    struct aoethread* t;
    int n = 0, a;
    int ret = 0;

    root.aoe_rq_cache = kmem_cache_create("aoe_rq_cache", sizeof (aoereq_t), sizeof (aoereq_t), SLAB_HWCACHE_ALIGN, NULL);
    if (root.aoe_rq_cache == NULL) return -ENOMEM;
    
    root.thread_percpu = (struct aoethread*)alloc_percpu(struct aoethread);
    if (root.thread_percpu == NULL) {
        ret = -ENOMEM;
        goto err1;
    }
    
    INIT_HLIST_HEAD(&root.devlist);
    spin_lock_init(&root.lock);
    
    ret = kobject_init_and_add(&root.kvblade_kobj, &kvblade_ktype_ops, NULL, "kvblade");
    if (ret) goto err2;

    for (n = 0; n < num_online_cpus(); n++) {
        t = (struct aoethread*)per_cpu_ptr(root.thread_percpu, n);
    
        memset(t, 0, sizeof(aoethread_t));
        init_completion(&t->ktrendez);

        t->task = kthread_create(kthread, t, "kvblade(%d)", n);
        if (t->task == NULL || IS_ERR(t->task)) {
            ret = -EAGAIN;
            goto err3;
        }
        
        kthread_bind(t->task, n);        
        wake_up_process(t->task);    
        wait_for_completion(&t->ktrendez);
        init_completion(&t->ktrendez); // for exit
    }

    dev_add_pack(&pt);
    return ret;
err3:
    for (a = 0; a < n; a++) {
        t = (struct aoethread*)per_cpu_ptr(root.thread_percpu, n);
        kthread_stop(t->task);
        wait_for_completion(&t->ktrendez);
    }
    kobject_del(&root.kvblade_kobj);
    kobject_put(&root.kvblade_kobj);
err2:
    free_percpu(root.thread_percpu);
err1:
    kmem_cache_destroy(root.aoe_rq_cache);
    return ret;
}

static __exit void kvblade_module_exit(void) {
    struct aoetarget *d, *nd;
    struct aoethread* t;
    int n;

    dev_remove_pack(&pt);
    
    spin_lock(&root.lock);
    rcu_read_lock();
    d = hlist_entry_safe(rcu_dereference_raw_notrace(hlist_first_rcu(&root.devlist)), aoetarget_t, node);
    rcu_assign_pointer(hlist_first_rcu(&root.devlist), NULL);
    rcu_read_unlock();
    spin_unlock(&root.lock);
    
    for (; d; d = nd) {
        nd = hlist_entry_safe(rcu_dereference_raw(hlist_next_rcu(&d->node)), aoetarget_t, node);
        while (count_busy(d)) {
            msleep(100);
        }
        
        call_rcu(&d->rcu, kvblade_del_rcu);
    }
    
    for (n = 0; n < num_online_cpus(); n++) {
        t = (struct aoethread*)per_cpu_ptr(root.thread_percpu, n);
        kthread_stop(t->task);
        wait_for_completion(&t->ktrendez);
    }
    
    kobject_del(&root.kvblade_kobj);
    kobject_put(&root.kvblade_kobj);
    
    if (root.thread_percpu != NULL) {
        free_percpu(root.thread_percpu);
        root.thread_percpu = NULL;
    }

    if (root.aoe_rq_cache != NULL) {
        kmem_cache_destroy(root.aoe_rq_cache);
        root.aoe_rq_cache = NULL;
    }
}

module_init(kvblade_module_init);
module_exit(kvblade_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sam Hopkins <sah@coraid.com>");
MODULE_AUTHOR("John Sharratt <johnathan.sharratt@gmail.com>");
MODULE_DESCRIPTION("Virtual EtherDrive(R) Blade");
