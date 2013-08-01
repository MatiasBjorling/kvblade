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
    /*Support our vendor-specific codes*/
    AOECMD_CREATETREE = 0xF0,   /*create a new tree*/
    AOECMD_REMOVETREE,          /*remove a tree and all its child nodes*/
    AOECMD_READNODE,            /*read data from an node*/
    AOECMD_INSERTNODE,          /*create a new node with some initial data*/
    AOECMD_UPDATENODE,          /*update the data of an existing node*/
    AOECMD_REMOVENODE,          /*remove the node and associated data*/
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
	unsigned char data[0];
};

struct aoe_atahdr {
	unsigned char aflags;
	unsigned char errfeat;
	unsigned char scnt;
	unsigned char cmdstat;
	unsigned char lba[6];
	unsigned char res[2];
	/*unsigned char data[0];*/ /*would give the wrong offset inside aoe_datahdr*/
};

struct aoe_treehdr {
    u64 tid;
    u64 nid;
    u64 off;
    u64 len;
    u32 err;
};

/*branch on AoE command value?*/
struct aoe_datahdr {
    union {
        struct aoe_atahdr ata;
        struct aoe_treehdr tree;
    };
    unsigned char data[0];
};

struct aoe_cfghdr {
	__be16 bufcnt;
	__be16 fwver;
	unsigned char scnt;
	unsigned char aoeccmd;
	__be16 cslen;
	unsigned char data[0];
};

