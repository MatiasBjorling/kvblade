/* Copyright (c) 2013 Coraid, Inc.  See COPYING for GPL terms. */
#define VERSION "85"
#define AOE_MAJOR 152
#define DEVICE_NAME "aoe"

/* set AOE_PARTITIONS to 1 to use whole-disks only
 * default is 16, which is 15 partitions plus the whole disk
 */
#ifndef AOE_PARTITIONS
#define AOE_PARTITIONS (16)
#endif

#define WHITESPACE " \t\v\f\n,"

enum {
	AOECMD_ATA,
	AOECMD_CFG,
	AOECMD_VEND_MIN = 0xf0,

	AOEFL_RSP = (1<<3),
	AOEFL_ERR = (1<<2),

	AOEAFL_EXT = (1<<6),
	AOEAFL_DEV = (1<<4),
	AOEAFL_ASYNC = (1<<1),
	AOEAFL_WRITE = (1<<0),

	AOECCMD_READ = 0,
	AOECCMD_TEST,
	AOECCMD_PTEST,
	AOECCMD_SET,
	AOECCMD_FSET,

	AOE_HVER = 0x10,
};

struct aoe_hdr {
	unsigned char dst[6];
	unsigned char src[6];
	__be16 type;
	unsigned char verfl;
	unsigned char err;
	__be16 major;
	unsigned char minor;
	unsigned char cmd;
	__be32 tag;
};

struct aoe_atahdr {
	unsigned char aflags;
	unsigned char errfeat;
	unsigned char scnt;
	unsigned char cmdstat;
	unsigned char lba0;
	unsigned char lba1;
	unsigned char lba2;
	unsigned char lba3;
	unsigned char lba4;
	unsigned char lba5;
	unsigned char res[2];
};

struct aoe_cfghdr {
	__be16 bufcnt;
	__be16 fwver;
	unsigned char scnt;
	unsigned char aoeccmd;
	unsigned char cslen[2];
};

enum {
	DEVFL_UP = 1,	/* device is installed in system and ready for AoE->ATA commands */
	DEVFL_TKILL = (1<<1),	/* flag for timer to know when to kill self */
	DEVFL_EXT = (1<<2),	/* device accepts lba48 commands */
	DEVFL_GDALLOC = (1<<3),	/* need to alloc gendisk */
	DEVFL_GD_NOW = (1<<4),	/* allocating gendisk */
	DEVFL_KICKME = (1<<5),	/* slow polling network card catch */
	DEVFL_NEWSIZE = (1<<6),	/* need to update dev size in block layer */
	DEVFL_FREEING = (1<<7),	/* set when device is being cleaned up */
	DEVFL_FREED = (1<<8),	/* device has been cleaned up */
};

enum {
	DEFAULTBCNT = 2 * 512,	/* 2 sectors */
	MIN_BUFS = 16,
	NTARGETS = 4,
	NAOEIFS = 8,
	NSKBPOOLMAX = 256,
	NFACTIVE = 61,

	TIMERTICK = HZ / 10,
	RTTSCALE = 8,
	RTTDSCALE = 3,
	RTTAVG_INIT = USEC_PER_SEC / 4 << RTTSCALE,
	RTTDEV_INIT = RTTAVG_INIT / 4,

	HARD_SCORN_SECS = 10,	/* try another remote port after this */
	MAX_TAINT = 1000,	/* cap on aoetgt taint */
};

enum frame_flags {
	FFL_PROBE = 1,
};

struct aoetgt {
	unsigned char addr[6];
	ushort nframes;		/* cap on frames to use */
	struct aoedev *d;			/* parent device I belong to */
	struct list_head ffree;			/* list of free frames */
	struct aoeif ifs[NAOEIFS];
	struct aoeif *ifp;	/* current aoeif in use */
	ushort nout;		/* number of AoE commands outstanding */
	ushort maxout;		/* current value for max outstanding */
	ushort next_cwnd;	/* incr maxout after decrementing to zero */
	ushort ssthresh;	/* slow start threshold */
	ulong falloc;		/* number of allocated frames */
	int taint;		/* how much we want to avoid this aoetgt */
	int minbcnt;
	int wpkts, rpkts;
	char nout_probes;
};