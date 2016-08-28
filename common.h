/*
 * Copyright (C) 2016 George Amvrosiadis.  All rights reserved.
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
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/mount.h>
#include <linux/vmalloc.h>
#include <linux/list_bl.h>

#ifdef DUET_DEBUG
#define duet_dbg(...)	pr_info(__VA_ARGS__)
#else
#define duet_dbg(...)
#endif

/*
 * Duet can be state-based, and/or event-based.
 *
 * Event-based Duet monitors events that occurred on a page, during its
 * time in the page cache: ADDED, REMOVED, DIRTY, and FLUSHED.
 *
 * State-based Duet monitors changes in the page cache since the last time
 * a notification was sent to the interested application. Registering for
 * EXIST informs the application of page additions or removals from the cache
 * (i.e. ADDED and REMOVED events cancel each other out if the application
 * hasn't been told in the meantime). Registering for MODIFIED events is a
 * similar model, where unreported DIRTY and FLUSHED events cancel each other.
 */
#define DUET_PAGE_ADDED		0x0001
#define DUET_PAGE_REMOVED	0x0002
#define DUET_PAGE_DIRTY		0x0004
#define DUET_PAGE_FLUSHED	0x0008
#define DUET_PAGE_MODIFIED	0x0010
#define DUET_PAGE_EXISTS	0x0020
#define DUET_FD_NONBLOCK	0x0040

/* Used only for page state */
#define DUET_MASK_VALID		0x8000

#define DUET_DEF_NUMTASKS	8

#define DUET_INODE_FREEING	(I_WILL_FREE | I_FREEING | I_CLEAR)

enum {
	DUET_STATUS_OFF = 0,
	DUET_STATUS_ON,
	DUET_STATUS_INIT,
	DUET_STATUS_CLEAN,
};

/*
 * Item struct returned for processing.
 * The UUID currently consists of the inode number and generation
 * (to help us identify cases of inode reuse), and the task id.
 * For state-based duet, we mark a page if it EXISTS or is MODIFIED.
 * For event-based duet, we mark a page added, removed, dirtied, and/or flushed.
 * Acceptable event combinations will differ based on the task's subscription.
 */
struct duet_uuid {
	unsigned long	ino;
	__u32		gen;
	__u8		tid;
};

struct duet_item {
	struct duet_uuid	uuid;
	unsigned long		idx;
	__u16			state;
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
	spinlock_t		lock;
	struct rb_root		root;
#ifdef CONFIG_DUET_STATS
	__u64			statcur;	/* Cur # of BitTree nodes */
	__u64			statmax;	/* Max # of BitTree nodes */
#endif /* CONFIG_DUET_STATS */
};

struct duet_task {
	__u8			id;

	int			fd;
	struct filename		*name;
	__u32			evtmask;	/* Mask of subscribed events */
	struct path		*regpath;	/* Registered path */
	char			*regpathname;	/* Registered path name */
	__u16			regpathlen;	/* Length of path name */

	/* Data structures linking task to framework */
	struct list_head	task_list;
	wait_queue_head_t	cleaner_queue;
	atomic_t		refcount;
	char			*pathbuf;	/* Buffer for getpath */
	struct duet_bittree	bittree;	/* Progress bitmap */
	wait_queue_head_t	event_queue;	/* for read and poll calls */

	/* Hash table bucket bitmap */
	spinlock_t		bbmap_lock;
	unsigned long		*bucket_bmap;
	unsigned long		bmap_cursor;
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
};

extern struct duet_info duet_env;

/* hook.c */
void duet_hook(__u16 evtcode, void *data);

/* hash.c */
int hash_init(void);
int hash_add(struct duet_task *task, struct duet_uuid uuid,
	     unsigned long idx, __u16 evtmask, short in_scan);
int hash_fetch(struct duet_task *task, struct duet_item *itm);
void hash_print(struct duet_task *task);

/* task.c -- not in linux/duet.h */
struct duet_task *duet_find_task(__u8 id);
void duet_task_dispose(struct duet_task *task);
int duet_register_task(struct filename *name, __u32 regmask, struct path *path);

/* ioctl.c */
long duet_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
int duet_shutdown(void);
int duet_online(void);

/* bittree.c */
int bittree_check_inode(struct duet_bittree *bt, struct duet_task *task,
			struct inode *inode);
int bittree_check(struct duet_bittree *bt, struct duet_uuid uuid,
		  struct duet_task *task);
int bittree_set(struct duet_bittree *bt, struct duet_uuid uuid);
int bittree_reset(struct duet_bittree *bt, struct duet_uuid uuid);
int bittree_print(struct duet_task *task);
void bittree_init(struct duet_bittree *bittree);
void bittree_destroy(struct duet_bittree *bittree);

/* path.c */
int do_find_path(struct duet_task *task, struct inode *inode,
		 int getpath, char *buf, int bufsize);
int duet_find_path(struct duet_task *task, struct duet_uuid uuid,
		   int getpath, char *buf, int bufsize);

/* debug.c */
struct duet_ioctl_status_args;

int duet_print_bmap(__u8 id);
int duet_print_item(__u8 id);
int duet_print_list(struct duet_ioctl_status_args __user *arg);

#endif /* _COMMON_H */
