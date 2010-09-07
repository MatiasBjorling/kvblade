/* Copyright (C) 2006 Coraid, Inc.  See COPYING for GPL terms. */

#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/workqueue.h>
#include <linux/blkdev.h>
#include <linux/netdevice.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/ata.h>
#include <linux/ctype.h>
#include "if_aoe.h"

#define xprintk(L, fmt, arg...) printk(L "kvblade: " "%s: " fmt, __func__, ## arg)
#define iprintk(fmt, arg...) xprintk(KERN_INFO, fmt, ## arg)
#define eprintk(fmt, arg...) xprintk(KERN_ERR, fmt, ## arg)
#define wprintk(fmt, arg...) xprintk(KERN_WARN, fmt, ## arg)
#define dprintk(fmt, arg...) if(0);else xprintk(KERN_DEBUG, fmt, ## arg)

#define nelem(A) (sizeof (A) / sizeof (A)[0])
#define MAXSECTORS(mtu) (((mtu) - sizeof (struct aoe_hdr) - sizeof (struct aoe_atahdr)) / 512)

static ssize_t show(struct kobject *, struct attribute *, char *);
static ssize_t store(struct kobject *, struct attribute *, const char *, size_t);
static void vrelease(struct kobject *);

enum {
	ATA_MODEL_LEN =	40,
	ATA_LBA28MAX = 0x0fffffff,
	ATA_IDNF = 1<<4,
	ATA_UNC = 1<<6,

	Aadd = 0,
	Adel,
	Ascnt,
	Abdev,
	Abpath,
	Amodel,
	Asn,
};

struct aoedev;
struct aoereq {
	struct bio *bio;
        struct sk_buff *skb;
	struct aoedev *d;	/* blech.  I'm blind to a cleaner solution. */
};

struct aoedev {
        struct kobject kobj;
	struct aoedev *next;
	struct net_device *netdev;
	struct block_device *blkdev;
	struct aoereq reqs[16];
        atomic_t busy;
	unsigned char config[1024];
	int nconfig;
	int major;
	int minor;

	char path[256];
	loff_t scnt;
	char model[ATA_MODEL_LEN];
	char sn[ATA_SERNO_LEN];
};

static struct attribute attrs[] = {
	[Aadd] = { .name = "add", .mode = S_IWUGO, .owner = THIS_MODULE }, 
	[Adel] = { .name = "del", .mode = S_IWUGO, .owner = THIS_MODULE },
	[Ascnt] = { .name = "scnt", .mode = S_IRUGO, .owner = THIS_MODULE },
	[Abdev] = { .name = "bdev", .mode = S_IRUGO, .owner = THIS_MODULE },
	[Abpath] = { .name = "bpath", .mode = S_IRUGO, .owner = THIS_MODULE },
	[Amodel] = { .name = "model", .mode = S_IRUGO|S_IWUGO, .owner = THIS_MODULE },
	[Asn] = { .name = "sn", .mode = S_IRUGO|S_IWUGO, .owner = THIS_MODULE },
};

static struct attribute *top_attrs[] = {
	attrs + Aadd,
	attrs + Adel,
	NULL
};

static struct attribute *vblade_attrs[] = {
	attrs + Ascnt,
	attrs + Abdev,
	attrs + Abpath,
	attrs + Amodel,
	attrs + Asn,
	NULL
};

static struct sysfs_ops ops = {
	.store = store,
	.show = show,
};

static struct kobj_type ktype = {
	.default_attrs = top_attrs,
	.sysfs_ops = &ops,
};

static struct kobject kobj = {
	.name = "kvblade",
	.ktype = &ktype,
};

static struct kobj_type vktype = {
	.release = vrelease,
	.default_attrs = vblade_attrs,
	.sysfs_ops = &ops,
};

static struct sk_buff_head skb_outq, skb_inq;
static spinlock_t lock;
static struct aoedev *devlist;
static struct completion ktrendez;
static struct task_struct *task;
static wait_queue_head_t ktwaitq;

static struct sk_buff *
skb_new(struct net_device *dev, ulong len)
{
	struct sk_buff *skb;

	if (len < ETH_ZLEN)
		len = ETH_ZLEN;

	skb = alloc_skb(len, GFP_ATOMIC);
	if (skb) {
		memset(skb->data, 0, len);
		skb->nh.raw = skb->mac.raw = skb->data;
		skb->dev = dev;
		skb->protocol = __constant_htons(ETH_P_AOE);
		skb->priority = 0;
		skb->next = skb->prev = NULL;
		skb->ip_summed = CHECKSUM_NONE;
		skb_put(skb, len);
	}
	return skb;
}

static void
announce(struct aoedev *d)
{
	struct sk_buff *skb;
	struct aoe_hdr *aoe;
	struct aoe_cfghdr *cfg;
	int len = sizeof *aoe + sizeof *cfg + d->nconfig;

	skb = skb_new(d->netdev, len);
	if (skb == NULL)
		return;

	aoe = (struct aoe_hdr *) skb->mac.raw;
	cfg = (struct aoe_cfghdr *) aoe->data;

	memset(aoe, 0, sizeof *aoe);
	memcpy(aoe->src, d->netdev->dev_addr, ETH_ALEN);
	memset(aoe->dst, 0xFF, ETH_ALEN);
	aoe->type = __constant_htons(ETH_P_AOE);
	aoe->verfl = AOE_HVER | AOEFL_RSP;
	aoe->major = cpu_to_be16(d->major);
	aoe->minor = d->minor;
	aoe->cmd = AOECMD_CFG;

	memset(cfg, 0, sizeof *cfg);
	cfg->bufcnt = cpu_to_be16(nelem(d->reqs));
	cfg->fwver = __constant_htons(0x0002);
	cfg->scnt = MAXSECTORS(d->netdev->mtu);
	cfg->aoeccmd = AOE_HVER;

	if (d->nconfig) {
		cfg->cslen = cpu_to_be16(d->nconfig);
		memcpy(cfg->data, d->config, d->nconfig);
	}
	skb_queue_tail(&skb_outq, skb);
	wake_up(&ktwaitq);
}

static char *
spncpy(char *d, const char *s, int n)
{
	char *r = d;

	memset(d, ' ', n);
	while (n-- > 0) {
		if (*s == '\0')
			break;
		*d++ = *s++;
	}
	return r;
}

static ssize_t
add(u32 major, u32 minor, char *ifname, char *path)
{
	struct block_device *bd;
	struct net_device *nd;
        struct aoedev *d, *td;

	bd = NULL;
	d = NULL;
	nd = dev_get_by_name(ifname);
	if (nd == NULL) {
		eprintk("add failed: interface %s not found.\n", ifname);
		return -ENOENT;
	}
	dev_put(nd);

	bd = open_bdev_excl(path, 0, NULL); //THIS_MODULE);
	if (!bd || IS_ERR(bd)) {
		eprintk("add failed: can't open block device %s: %ld\n", path, PTR_ERR(bd));
		return -ENOENT;
	}
	if (bd->bd_disk->capacity == 0) {
		eprintk("add failed: zero sized block device.\n");
		close_bdev_excl(bd);
		return -ENOENT;
	}
	d = kmalloc(sizeof *d, GFP_KERNEL);
	if (!d) {
		eprintk("add failed: kmalloc error for %d.%d\n", major, minor);
		close_bdev_excl(bd);
		return -ENOMEM;
	}

	spin_lock(&lock);
	for (td=devlist; td; td=td->next)
		if (td->major == major)
		if (td->minor == minor)
		if (td->netdev == nd) {
			spin_unlock(&lock);
			close_bdev_excl(bd);
			kfree(d);
			eprintk("add failed: device %d.%d already exists on %s.\n",
				major, minor, ifname);
			return -EEXIST;
		}
        memset(d, 0, sizeof *d);
        atomic_set(&d->busy, 0);
	d->blkdev = bd;
	d->netdev = nd;
	d->major = major;
	d->minor = minor;
        d->scnt = bd->bd_disk->capacity;
	strncpy(d->path, path, nelem(d->path)-1);
	spncpy(d->model, "EtherDrive(R) kvblade", nelem(d->model));
	spncpy(d->sn, "SN HERE", nelem(d->sn));
	kobject_init(&d->kobj);
	d->kobj.ktype = &vktype;
	d->kobj.parent = &kobj;
	kobject_set_name(&d->kobj, "%d.%d@%s", major, minor, ifname);
	d->next = devlist;
	devlist = d;
	spin_unlock(&lock);
	kobject_add(&d->kobj);

	dprintk("added %s as %d.%d@%s: %Lu sectors.\n",
		path, major, minor, ifname, d->scnt);
	announce(d);
	return 0;
}

static ssize_t
del(u32 major, u32 minor, char *ifname)
{
        struct aoedev *d, **b;
	int error;

	b = &devlist;
	d = devlist;
	spin_lock(&lock);
	for (; d; b=&d->next, d=*b)
		if (d->major == major)
		if (d->minor == minor)
		if (strcmp(d->netdev->name, ifname) == 0)
			break;
	if (d == NULL) {
		eprintk("del failed: device %d.%d@%s not found.\n", 
			major, minor, ifname);
		error = -ENOENT;
		goto exit;
	} else if (atomic_read(&d->busy)) {
		eprintk("del failed: device %d.%d@%s is busy.\n",
			major, minor, ifname);
		error = -EBUSY;
		goto exit;
	}
	*b = d->next;
	spin_unlock(&lock);
	close_bdev_excl(d->blkdev);
	kobject_del(&d->kobj);
	kobject_put(&d->kobj);
	return 0;
exit:
	spin_unlock(&lock);
	return error;
}

static ssize_t
args(char *p, char *argv[], int argv_max)
{
	int argc = 0;

	while (*p) {
		while (*p && isspace(*p))
			++p;
		if (*p == '\0')
			break;
		if (argc < argv_max)
			argv[argc++] = p;
		else {
			eprintk("too many args!\n");
			return -1;
		}
		while (*p && !isspace(*p))
			++p;
		if (*p)
			*p++ = '\0';
	}
	return argc;
}

static ssize_t
show(struct kobject *kobj, struct attribute *attr, char *data)
{
	struct aoedev *d;

	d = (struct aoedev *) kobj;
	switch (attr - attrs) {
	default:
	case Aadd:
	case Adel:
		return 0;
	case Ascnt:
		return sprintf(data, "%Ld\n", d->scnt);
	case Abdev:
		return print_dev_t(data, d->blkdev->bd_dev);
	case Abpath:
		return sprintf(data, "%.*s\n", nelem(d->path), d->path);
	case Amodel:
		return sprintf(data, "%.*s\n", nelem(d->model), d->model);
	case Asn:
		return sprintf(data, "%.*s\n", nelem(d->sn), d->sn);
	}
}

static ssize_t
store(struct kobject *kobj, struct attribute *attr, const char *data, size_t len)
{
	struct aoedev *d;
	char *argv[16];
	char *p;
	int error;

	error = 0;
	p = kmalloc(len+1, GFP_KERNEL);
	memcpy(p, data, len);
	p[len] = '\0';
	d = (struct aoedev *) kobj;

	switch (attr - attrs) {
	default:
	case Ascnt:
	case Abdev:
	case Abpath:
		error = -EPERM;
		break;
	case Aadd:
		if (args(p, argv, nelem(argv)) != 4) {
			eprintk("bad arg count for add\n");
			error = -EINVAL;
		} else
			error = add(simple_strtoul(argv[0], NULL, 0),
				simple_strtoul(argv[1], NULL, 0),
				argv[2], argv[3]);
		break;
	case Adel:
		if (args(p, argv, nelem(argv)) != 3) {
			eprintk("bad arg count for del\n");
			error = -EINVAL;
		} else
			error = del(simple_strtoul(argv[0], NULL, 0),
				simple_strtoul(argv[1], NULL, 0),
				argv[2]);
		break;
	case Amodel:
		spncpy(d->model, data, nelem(d->model));
		break;
	case Asn:
		spncpy(d->sn, data, nelem(d->sn));
		break;
	}
	kfree(p);
	return error ? error : len;
}

static void
vrelease(struct kobject *kobj)
{
	kfree(kobj);
}

static void
setfld(u16 *a, int idx, int len, char *str)
{
	u8 *p;

	for (p = (u8*)(a + idx); len; p += 2, len -= 2) {
		p[1] = *str ? *str++ : ' ';
		p[0] = *str ? *str++ : ' ';
	}
}

static int
ata_identify(struct aoedev *d, struct aoe_atahdr *ata)
{
	char 	buf[64];
	u16     *words  = (u16 *)ata->data;
	u8      *cp;
	loff_t  scnt;

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
	setfld(words, 23,  8, buf);
	setfld(words, 27, nelem(d->model), d->model);
	setfld(words, 10, nelem(d->sn), d->sn);

	scnt = d->scnt;
	cp = (u8 *)&words[100];
	*cp++ = scnt;
	*cp++ = (scnt >>= 8);
	*cp++ = (scnt >>= 8);
	*cp++ = (scnt >>= 8);
	*cp++ = (scnt >>= 8);
	*cp++ = (scnt >>= 8);

	scnt = d->scnt;
	cp = (u8 *)&words[60];

	if (scnt & ~ATA_LBA28MAX)
		scnt = ATA_LBA28MAX;
	*cp++ = scnt;
	*cp++ = (scnt >>= 8);
	*cp++ = (scnt >>= 8);
	*cp++ = (scnt >>= 8) & 0xf;

	return 512;
}

static int
ata_io_complete(struct bio *bio, unsigned int bytes, int error)
{
	struct aoereq *rq;
	struct aoedev *d;
	struct sk_buff *skb;
	struct aoe_hdr *aoe;
	struct aoe_atahdr *ata;
	int len;

	if (!error)
	if (bio->bi_size)
		return 1;

	rq = bio->bi_private;
	d = rq->d;
	skb = rq->skb;
	aoe = (struct aoe_hdr *) skb->mac.raw;
	ata = (struct aoe_atahdr *) aoe->data;
	len = sizeof *aoe + sizeof *ata;
	if (bio_flagged(bio, BIO_UPTODATE)) {
		if (bio_rw(bio) == READ)
			len += bytes;
		ata->scnt = 0;
		ata->cmdstat = ATA_DRDY;
		ata->errfeat = 0;
		// should increment lba here, too
	} else {
		eprintk("I/O error %d on %s\n", error, d->kobj.name);
		ata->cmdstat = ATA_ERR | ATA_DF;
		ata->errfeat = ATA_UNC | ATA_ABORTED;
	}
	bio_put(bio);
	rq->skb = NULL;
	atomic_dec(&d->busy);
	skb_trim(skb, len);
	skb_queue_tail(&skb_outq, skb);
	wake_up(&ktwaitq);
	return 0;
}

static inline loff_t
readlba(u8 *lba)
{
	loff_t n = 0ULL;
	int i;

	for (i=5; i>=0; i--) {
		n <<= 8;
		n |= lba[i];
	}
	return n;
}

static struct sk_buff *
ata(struct aoedev *d, struct sk_buff *skb)
{
	struct aoe_hdr *aoe;
	struct aoe_atahdr *ata;
	struct aoereq *rq, *e;
	struct bio *bio;
	sector_t lba;
	int len, rw;
	struct page *page;
	ulong bcnt, offset;

	aoe = (struct aoe_hdr *) skb->mac.raw;
	ata = (struct aoe_atahdr *) aoe->data;
	lba = readlba(ata->lba);
	len = sizeof *aoe + sizeof *ata;
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
		if ((lba + ata->scnt) > d->scnt) {
			eprintk("sector I/O is out of range: %Lu (%d), max %Lu\n",
				lba, ata->scnt, d->scnt);
			ata->cmdstat = ATA_ERR;
			ata->errfeat = ATA_IDNF;
			break;
		}
		rq = d->reqs;
		e = rq + nelem(d->reqs);
		for (; rq<e; rq++)
			if (rq->skb == NULL)
				break;
		if (rq == e)
			goto drop;
		
		bio = bio_alloc(GFP_ATOMIC, 1);
		if (bio == NULL) {
			eprintk("can't alloc bio\n");
			goto drop;
		}
		rq->bio = bio;
		rq->d = d;
		bio->bi_sector = lba;
		bio->bi_bdev = d->blkdev;
		bio->bi_end_io = ata_io_complete;
		bio->bi_private = rq;
		page = virt_to_page(ata->data);
		bcnt = ata->scnt << 9;
		offset = offset_in_page(ata->data);
		if (bio_add_page(bio, page, bcnt, offset) < bcnt) {
			eprintk("can't bio_add_page for %d sectors\n", ata->scnt);
			bio_put(bio);
			goto drop;
		}
		rq->skb = skb;
		atomic_inc(&d->busy);
		submit_bio(rw, bio);
		return NULL;
	default:
		eprintk("unknown ATA command 0x%02X\n", ata->cmdstat);
		ata->cmdstat = ATA_ERR;
		ata->errfeat = ATA_ABORTED;
		break;
	case ATA_CMD_ID_ATA:
		len += ata_identify(d, ata);
	case ATA_CMD_FLUSH:
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

static struct sk_buff *
cfg(struct aoedev *d, struct sk_buff *skb)
{
	struct aoe_hdr *aoe;
	struct aoe_cfghdr *cfg;
	int len, cslen, ccmd;

	aoe = (struct aoe_hdr *) skb->mac.raw;
	cfg = (struct aoe_cfghdr *) aoe->data;
	cslen = ntohs(cfg->cslen);
	ccmd = cfg->aoeccmd & 0xf;
	len = sizeof *aoe;

	cfg->bufcnt = htons(nelem(d->reqs));
	cfg->scnt = MAXSECTORS(d->netdev->mtu);
	cfg->fwver = __constant_htons(0x0002);
	cfg->aoeccmd = AOE_HVER;

	if (cslen > nelem(d->config))
		goto drop;

	switch (ccmd) {
	case AOECCMD_TEST:
		if (d->nconfig != cslen)
			goto drop;
		// fall thru
	case AOECCMD_PTEST:
		if (cslen > d->nconfig)
			goto drop;
		if (memcmp(cfg->data, d->config, cslen) != 0)
			goto drop;
		// fall thru
	case AOECCMD_READ:
		cfg->cslen = cpu_to_be16(d->nconfig);
		memcpy(cfg->data, d->config, d->nconfig);
		len += sizeof *cfg + d->nconfig;
		break;
	case AOECCMD_SET:
		if (d->nconfig)
		if (d->nconfig != cslen || memcmp(cfg->data, d->config, cslen) != 0) {
			aoe->verfl |= AOEFL_ERR;
			aoe->err = AOEERR_CFG;
			break;
		}
		// fall thru
	case AOECCMD_FSET:
		d->nconfig = cslen;
		memcpy(d->config, cfg->data, cslen);
		len += sizeof *cfg + cslen;
		break;
	default:
		aoe->verfl |= AOEFL_ERR;
		aoe->err = AOEERR_ARG;
	}
	skb_trim(skb, len);
	return skb;
drop:
	dev_kfree_skb(skb);
	return NULL;
}

static struct sk_buff *
make_response(struct sk_buff *skb, int major, int minor)
{
	struct aoe_hdr *aoe;
	struct sk_buff *rskb;

	rskb = skb_new(skb->dev, skb->dev->mtu);
	if (rskb == NULL)
		return NULL;
	aoe = (struct aoe_hdr *) rskb->mac.raw;
	memcpy(rskb->mac.raw, skb->mac.raw, skb->len);
	memcpy(aoe->dst, aoe->src, ETH_ALEN);
	memcpy(aoe->src, skb->dev->dev_addr, ETH_ALEN);
	aoe->type = __constant_htons(ETH_P_AOE);
	aoe->verfl = AOE_HVER | AOEFL_RSP;
	aoe->major = cpu_to_be16(major);
	aoe->minor = minor;
	aoe->err = 0;
	return rskb;
}

static int
rcv(struct sk_buff *skb, struct net_device *ndev, struct packet_type *pt, struct net_device *orig_dev)
{
	struct aoe_hdr *aoe;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (skb == NULL) {
		dprintk("share check returned nil\n");
		return -ENOMEM;
	}
	if (skb_linearize(skb) < 0) {
		dev_kfree_skb(skb);
		return -ENOMEM;
	}
	skb_push(skb, ETH_HLEN);

	aoe = (struct aoe_hdr *) skb->mac.raw;
	if (~aoe->verfl & AOEFL_RSP) {
		skb_queue_tail(&skb_inq, skb);
		wake_up(&ktwaitq);
	} else {
		dev_kfree_skb(skb);
	}
	return 0;
}

static void
ktrcv(struct sk_buff *skb)
{
	struct sk_buff *rskb;
	struct aoedev *d;
	struct aoe_hdr *aoe;
	int major, minor;

	aoe = (struct aoe_hdr *) skb->mac.raw;
	major = be16_to_cpu(aoe->major);
	minor = aoe->minor;
      	spin_lock(&lock);
	for (d=devlist; d; d=d->next) {
		if ((major != d->major && major != 0xffff)
		|| (minor != d->minor && minor != 0xff)
		|| (skb->dev != d->netdev))
			continue;
		rskb = make_response(skb, d->major, d->minor);
		if (rskb == NULL)
			continue;
		switch (aoe->cmd) {
		case AOECMD_ATA:
			rskb = ata(d, rskb);
			break;
		case AOECMD_CFG:
			rskb = cfg(d, rskb);
			break;
		default:
			dev_kfree_skb(rskb);
			continue;
		}
		if (rskb)
			skb_queue_tail(&skb_outq, rskb);
	}
	spin_unlock(&lock);
	dev_kfree_skb(skb);
}

static int
kthread(void *errorparameternameomitted)
{
	struct sk_buff *iskb, *oskb;
	DECLARE_WAITQUEUE(wait, current);
	sigset_t blocked;

#ifdef PF_NOFREEZE
	current->flags |= PF_NOFREEZE;
#endif
	set_user_nice(current, -5);
	sigfillset(&blocked);
	sigprocmask(SIG_BLOCK, &blocked, NULL);
	flush_signals(current);
	complete(&ktrendez);
	do {
		__set_current_state(TASK_RUNNING);
		do {
			if ((iskb = skb_dequeue(&skb_inq)))
				ktrcv(iskb);
			if ((oskb = skb_dequeue(&skb_outq)))
				dev_queue_xmit(oskb);
		} while (iskb || oskb);
		set_current_state(TASK_INTERRUPTIBLE);
		add_wait_queue(&ktwaitq, &wait);
		schedule();
		remove_wait_queue(&ktwaitq, &wait);
	} while (!kthread_should_stop());
	__set_current_state(TASK_RUNNING);
	complete(&ktrendez);
	return 0;
}

static struct packet_type pt = {
	.type = __constant_htons(ETH_P_AOE),
	.func = rcv,
};

static int __init
init(void)
{
	skb_queue_head_init(&skb_outq);
	skb_queue_head_init(&skb_inq);
	spin_lock_init(&lock);
	init_completion(&ktrendez);
	init_waitqueue_head(&ktwaitq);
	task = kthread_run(kthread, NULL, "kvblade");
	if (task == NULL || IS_ERR(task))
		return -EAGAIN;
	kobject_register(&kobj);
	wait_for_completion(&ktrendez);
	init_completion(&ktrendez);	// for exit
	dev_add_pack(&pt);
	return 0;
}

static void
exit(void)
{
	struct aoedev *d, *nd;

	dev_remove_pack(&pt);
	spin_lock(&lock);
	d = devlist;
	devlist = NULL;
	spin_unlock(&lock);
	for (; d; d=nd) {
		nd = d->next;
		while (atomic_read(&d->busy))
			msleep(100);
		close_bdev_excl(d->blkdev);
		kobject_unregister(&d->kobj);
	}
	kthread_stop(task);
	wait_for_completion(&ktrendez);
	skb_queue_purge(&skb_outq);
	skb_queue_purge(&skb_inq);
	kobject_unregister(&kobj);
}

module_init(init);
module_exit(exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sam Hopkins <sah@coraid.com>");
MODULE_DESCRIPTION("Virtual EtherDrive(R) Blade");

