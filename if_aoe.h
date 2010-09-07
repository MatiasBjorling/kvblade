/* Copyright (C) 2006 Coraid, Inc.  See COPYING for GPL terms. */

/* apparently a compatibility hack */
#ifndef ETH_P_AOE
#define ETH_P_AOE 0x88a2
#endif

enum {
	AOECMD_ATA,
	AOECMD_CFG,

	AOECCMD_READ = 0,
	AOECCMD_TEST,
	AOECCMD_PTEST,
	AOECCMD_SET,
	AOECCMD_FSET,

	AOEERR_CMD= 1,
	AOEERR_ARG,
	AOEERR_DEV,
	AOEERR_CFG,
	AOEERR_VER,

	AOEFL_RSP = 1<<3,
	AOEFL_ERR = 1<<2,

	AOE_HVER = 0x20,
};

struct aoe_hdr {
	unsigned char dst[6];
        unsigned char src[6];
        unsigned short type;
        unsigned char verfl;
        unsigned char err;
        unsigned short major;
        unsigned char minor;
	unsigned char cmd;
	unsigned long tag;
	unsigned char data[0];
};

struct aoe_atahdr {
	unsigned char aflags;
	unsigned char errfeat;
	unsigned char scnt;
	unsigned char cmdstat;
	unsigned char lba[6];
	unsigned char res[2];
	unsigned char data[0];
};

struct aoe_cfghdr {
        unsigned short bufcnt;
	unsigned short fwver;
        unsigned char scnt;
        unsigned char aoeccmd;
        unsigned short cslen;
	unsigned char data[0];
};

