/*
 * Copyright (C) 2014-2015 George Amvrosiadis.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 */
#ifndef _COMMON_H
#define _COMMON_H

#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/list_bl.h>
#include <linux/bitmap.h>
#include <linux/rculist.h>
#include <linux/duet.h>

#ifdef DUET_DEBUG
#define duet_dbg(...)	printk(__VA_ARGS__)
#else
#define duet_dbg(...)
#endif

/*
 * Duet can be either state- and/or event-based.
 * Event-based Duet monitors events that have happened on a page, which include
 * all events in the lifetime of a cache page: ADDED, REMOVED, DIRTY, FLUSHED.
 * Add and remove events are triggered when a page __descriptor__ is inserted or
 * removed from the page cache. Modification events are triggered when the page
 * is dirtied (nb: during writes, pages are added, then dirtied), and flush
 * events are triggered when a page is marked for writeback.
 * State-based Duet monitors changes in the page cache. Registering for EXISTS
 * events means that fetch will be returning ADDED or REMOVED events if the
 * state of the page changes since the last fetch (i.e. the two events cancel
 * each other out). Registering for MODIFIED events means that fetch will be
 * returning DIRTY or FLUSHED events if the state of the page changes since the
 * last fetch.
 */
#define DUET_PAGE_ADDED		0x0001
#define DUET_PAGE_REMOVED	0x0002
#define DUET_PAGE_DIRTY		0x0004
#define DUET_PAGE_FLUSHED	0x0008
#define DUET_PAGE_MODIFIED	0x0010
#define DUET_PAGE_EXISTS	0x0020

/* Used only for page state */
#define DUET_MASK_VALID		0x8000

/* Used only during registration */
#define DUET_REG_SBLOCK		0x8000
#define DUET_FILE_TASK		0x10000	/* we register a 32-bit flag due to this */

#define DUET_UUID_INO(uuid)	((unsigned long)(uuid & 0xffffffff))
#define DUET_UUID_GEN(uuid)	((unsigned long)(uuid >> 32))

#define DUET_DEF_NUMTASKS	8
#define MAX_NAME		22
#define MAX_PATH		1024
#define DUET_BITS_PER_NODE	(32768 * 8)	/* 32KB bitmaps */

/* Some useful flags for clearing bitmaps */
#define BMAP_SEEN	0x1
#define BMAP_RELV	0x2
#define BMAP_DONE	0x4

#define DUET_INODE_FREEING	(I_WILL_FREE | I_FREEING | I_CLEAR)
#define DUET_GET_UUID(inode)	(((unsigned long long) inode->i_generation << 32) | \
				(unsigned long long) inode->i_ino)

enum {
	DUET_STATUS_OFF = 0,
	DUET_STATUS_ON,
	DUET_STATUS_INIT,
	DUET_STATUS_CLEAN,
};

/*
 * Item struct returned for processing.
 * The UUID currently consists of the inode number and generation.
 * File events are communicated under idx zero.
 * For state-based duet, we mark a page if it EXISTS or is MODIFIED.
 * For event-based duet, we mark a page added, removed, dirtied, and/or flushed.
 * Acceptable event combinations will differ based on the task's subscription.
 */
struct duet_item {
	unsigned long long	uuid;
	unsigned long		idx;
	__u16			state;
};

/*
 * InodeTree structure. Two red-black trees, one sorted by the number of pages
 * in memory, the other sorted by inode number.
 */
struct inode_tree {
	struct rb_root sorted;
	struct rb_root inodes;
};

/*
 * Red-black bitmap tree node.
 * Represents the range starting from idx. For block tasks, only the done
 * bitmap is used. For file tasks, the seen and relv (relevant) bitmaps are
 * also used. The semantics of different states are listed below, where an
 * item can be in the unknown state due to a bitmap reset, or because it hasn't
 * been encountered yet.
 * - !SEEN && !RELV && !DONE: Item in unknown state
 * - !SEEN && !RELV &&  DONE: Item processed, but in unknown state
 * -  SEEN && !RELV && !DONE: Item not relevant to the task
 * -  SEEN &&  RELV && !DONE: Item is relevant, but not processed
 * -  SEEN &&  RELV &&  DONE: Item is relevant, and has already been processed
 */
struct bmap_rbnode {
	__u64		idx;
	struct rb_node	node;
	unsigned long	*seen;
	unsigned long	*relv;
	unsigned long	*done;
};

struct item_hnode {
	struct hlist_bl_node	node;
	struct duet_item	item;
	__u8			refcount;
	__u16			*state;		/* One entry per task */
};

struct duet_bittree {
	__u8			is_file;	/* Task type, as in duet_task */
	__u32			range;
	spinlock_t		lock;
	struct rb_root		root;
#ifdef CONFIG_DUET_STATS
	__u64			statcur;	/* Cur # of BitTree nodes */
	__u64			statmax;	/* Max # of BitTree nodes */
#endif /* CONFIG_DUET_STATS */
};

struct duet_task {
	__u8			id;
	__u8			is_file;	/* Type: set if file task */
	char			name[MAX_NAME];
	struct list_head	task_list;
	wait_queue_head_t	cleaner_queue;
	atomic_t		refcount;
	__u16			evtmask;	/* Mask of subscribed events */
	char			*pathbuf;	/* Buffer for getpath */

	/* Optional heuristics to filter the events received */
	struct super_block	*f_sb;		/* Filesystem superblock */
	struct dentry		*p_dentry;	/* Parent dentry */
	struct vfsmount		*p_mnt;		/* Parent VFS mount point */
	char			*parbuf;	/* Buffer for registered path */
	__u16			parbuflen;	/* Length of path buffer */
	__u8			use_imap;	/* Use the inode bitmap */

	/* Hash table bucket bitmap */
	spinlock_t		bbmap_lock;
	unsigned long		*bucket_bmap;
	unsigned long		bmap_cursor;

	/* BitTree -- progress bitmap tree */
	struct duet_bittree	bittree;
};

struct duet_info {
	atomic_t		status;
	__u8			numtasks;	/* Number of concurrent tasks */

	/*
	 * Access to the task list is synchronized via a mutex. However, any
	 * operations that are on-going for a task (e.g. fetch) will increase
	 * its refcount. This refcount is consulted when disposing of the task.
	 */
	struct mutex		task_list_mutex;
	struct list_head	tasks;

	/* ItemTable -- Global page state hash table */
	struct hlist_bl_head	*itm_hash_table;
	unsigned long		itm_hash_size;
	unsigned long		itm_hash_shift;
	unsigned long		itm_hash_mask;
#ifdef CONFIG_DUET_STATS
	unsigned long		itm_stat_lkp;	/* total lookups per request */
	unsigned long		itm_stat_num;	/* number of node requests */
#endif /* CONFIG_DUET_STATS */
};

extern struct duet_info duet_env;
extern int d_find_path(struct inode *cnode, struct dentry *p_dentry,
			int getpath, char *buf, int len, char **p);

/* hook.c */
void duet_hook(__u16 evtcode, void *data);

/* hash.c */
int hash_init(void);
int hash_add(struct duet_task *task, unsigned long long uuid, unsigned long idx,
	__u16 evtmask, short in_scan);
int hash_fetch(struct duet_task *task, struct duet_item *itm);
void hash_print(struct duet_task *task);

/* task.c -- not in linux/duet.h */
struct duet_task *duet_find_task(__u8 taskid);
void duet_task_dispose(struct duet_task *task);

/* ioctl.c */
int duet_bootstrap(__u8 numtasks);
int duet_shutdown(void);
long duet_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
int do_find_path(struct duet_task *task, struct inode *inode, int getpath,
	char *path);
int duet_find_path(struct duet_task *task, unsigned long long uuid, int getpath,
	char *path);

/* bittree.c */
int bittree_check_inode(struct duet_bittree *bt, struct duet_task *task,
	struct inode *inode);
int bittree_check(struct duet_bittree *bt, __u64 idx, __u32 len,
	struct duet_task *task);
int bittree_set_done(struct duet_bittree *bt, __u64 idx, __u32 len);
int bittree_unset_done(struct duet_bittree *bt, __u64 idx, __u32 len);
int bittree_check_done_bit(struct duet_bittree *bt, __u64 idx, __u32 len);
int bittree_set_relv(struct duet_bittree *bt, __u64 idx, __u32 len);
int bittree_unset_relv(struct duet_bittree *bt, __u64 idx, __u32 len);
int bittree_clear_bits(struct duet_bittree *bt, __u64 idx, __u32 len);
int bittree_clear_bitmap(struct duet_bittree *bt, __u8 flags);

int bittree_print(struct duet_task *task);
void bittree_init(struct duet_bittree *bittree, __u32 range, __u8 is_file);
void bittree_destroy(struct duet_bittree *bittree);

/* itree.c */
/* InodeTree interface functions */
typedef int (itree_get_inode_t)(void *, unsigned long, struct inode **);
void itree_init(struct inode_tree *itree);
int itree_update(struct inode_tree *itree, __u8 taskid,
	itree_get_inode_t *itree_get_inode, void *ctx);
int itree_fetch(struct inode_tree *itree, __u8 taskid, struct inode **inode,
	itree_get_inode_t *itree_get_inode, void *ctx);
void itree_teardown(struct inode_tree *itree);

/* Framework interface functions */
int duet_register(char *path, __u32 regmask, __u32 bitrange, const char *name,
		  __u8 *taskid);
int duet_deregister(__u8 taskid);
int duet_fetch(__u8 taskid, struct duet_item *items, __u16 *count);
int duet_check_done(__u8 taskid, __u64 idx, __u32 count);
int duet_set_done(__u8 taskid, __u64 idx, __u32 count);
int duet_unset_done(__u8 taskid, __u64 idx, __u32 count);
int duet_online(void);

/* Framework debugging functions */
int duet_print_bitmap(__u8 taskid);
int duet_print_events(__u8 taskid);

#endif /* _COMMON_H */
