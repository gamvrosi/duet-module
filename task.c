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

#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include "common.h"

/*
 * To synchronize access to the task list and structures without compromising
 * scalability, a two-level approach is used. At the task list level, which is
 * rarely updated, RCU is used. For the task structures, we use traditional
 * reference counting. The two techniques are interweaved to achieve overall
 * consistency.
 */

static int process_inode(struct duet_task *task, struct inode *inode)
{
	struct radix_tree_iter iter;
	void **slot;
	__u16 state;

	/* For file tasks, use the inode bitmap to decide whether to skip inode */
	if (task->is_file && (bittree_check_inode(&task->bittree, task, inode) == 1))
		return 0;

	/* Go through all pages of this inode */
	rcu_read_lock();
	radix_tree_for_each_slot(slot, &inode->i_mapping->page_tree, &iter, 0) {
		struct page *page;

		page = radix_tree_deref_slot(slot);
		if (unlikely(!page))
			continue;

		if (radix_tree_exception(page)) {
			if (radix_tree_deref_retry(page)) {
				slot = radix_tree_iter_retry(&iter);
				continue;
			}
			/*
			 * A shadow entry of a recently evicted page, or a swap entry
			 * from shmem/tmpfs. Skip over it.
			 */
			continue;
		}

		state = DUET_PAGE_ADDED;
		if (PageDirty(page))
			state |= DUET_PAGE_DIRTY;
		hash_add(task, DUET_GET_UUID(inode), page->index, state, 1);
	}
	rcu_read_unlock();

	return 0;
}

/* Scan through the page cache, and populate the task's tree. */
static int scan_page_cache(struct duet_task *task)
{
	struct inode *inode, *prev = NULL;

	printk(KERN_INFO "duet: page cache scan started\n");

	spin_lock(&task->f_sb->s_inode_list_lock);
	list_for_each_entry(inode, &task->f_sb->s_inodes, i_sb_list) {
		struct address_space *mapping = inode->i_mapping;

		spin_lock(&inode->i_lock);
		if (inode->i_state & DUET_INODE_FREEING || mapping->nrpages == 0) {
			spin_unlock(&inode->i_lock);
			continue;
		}
		atomic_inc(&inode->i_count);
		spin_unlock(&inode->i_lock);
		spin_unlock(&task->f_sb->s_inode_list_lock);

		/*
		 * We are holding a reference to inode so it won't be removed from
		 * s_inodes list while we don't hold the s_inode_list_lock. We cannot
		 * iput the inode now, though, as we may be holding the last reference.
		 * We will iput it after the iteration is done.
		 */

		iput(prev);
		prev = inode;

		process_inode(task, inode);

		spin_lock(&task->f_sb->s_inode_list_lock);
	}
	spin_unlock(&task->f_sb->s_inode_list_lock);
	iput(prev);

	printk(KERN_INFO "duet: page cache scan finished\n");

	return 0;
}

/* Find task and increment its refcount */
struct duet_task *duet_find_task(__u8 taskid)
{
	struct duet_task *cur, *task = NULL;

	rcu_read_lock();
	list_for_each_entry_rcu(cur, &duet_env.tasks, task_list) {
		if (cur->id == taskid) {
			task = cur;
			atomic_inc(&task->refcount);
			break;
		}
	}
	rcu_read_unlock();

	return task;
}

/* Do a preorder print of the BitTree */
int duet_print_bitmap(__u8 taskid)
{
	struct duet_task *task;

	task = duet_find_task(taskid);
	if (!task)
		return -ENOENT;

	if (bittree_print(task)) {
		printk(KERN_ERR "duet: failed to print BitTree for task %d\n",
			task->id);
		return -1;
	}

	/* decref and wake up cleaner if needed */
	if (atomic_dec_and_test(&task->refcount))
		wake_up(&task->cleaner_queue);

	return 0;
}
EXPORT_SYMBOL_GPL(duet_print_bitmap);

/* Do a preorder print of the global hash table */
int duet_print_events(__u8 taskid)
{
	struct duet_task *task = duet_find_task(taskid);
	if (!task)
		return -ENOENT;

	hash_print(task);

	/* decref and wake up cleaner if needed */
	if (atomic_dec_and_test(&task->refcount))
		wake_up(&task->cleaner_queue);

	return 0;
}
EXPORT_SYMBOL_GPL(duet_print_events);

/* Checks whether items in the [idx, idx+count) range are done */
int duet_check_done(__u8 taskid, __u64 idx, __u32 count)
{
	int ret = 0;
	struct duet_task *task;

	if (!duet_online())
		return -1;

	task = duet_find_task(taskid);
	if (!task)
		return -ENOENT;

	ret = bittree_check(&task->bittree, idx, count, task);

	/* decref and wake up cleaner if needed */
	if (atomic_dec_and_test(&task->refcount))
		wake_up(&task->cleaner_queue);

	return ret;
}
EXPORT_SYMBOL_GPL(duet_check_done);

/* Unmarks items in the [idx, idx+count) range, i.e. not done */
int duet_unset_done(__u8 taskid, __u64 idx, __u32 count)
{
	int ret = 0;
	struct duet_task *task;

	if (!duet_online())
		return -1;

	task = duet_find_task(taskid);
	if (!task)
		return -ENOENT;

	ret = bittree_unset_done(&task->bittree, idx, count);

	/* decref and wake up cleaner if needed */
	if (atomic_dec_and_test(&task->refcount))
		wake_up(&task->cleaner_queue);

	return ret;
}
EXPORT_SYMBOL_GPL(duet_unset_done);

/* Mark items in the [idx, idx+count) range, i.e. done */
int duet_set_done(__u8 taskid, __u64 idx, __u32 count)
{
	int ret = 0;
	struct duet_task *task;

	if (!duet_online())
		return -1;

	task = duet_find_task(taskid);
	if (!task)
		return -ENOENT;

	ret = bittree_set_done(&task->bittree, idx, count);

	/* decref and wake up cleaner if needed */
	if (atomic_dec_and_test(&task->refcount))
		wake_up(&task->cleaner_queue);

	return ret;
}
EXPORT_SYMBOL_GPL(duet_set_done);

/* Properly allocate and initialize a task struct */
static int duet_task_init(struct duet_task **task, const char *name,
	__u32 regmask, __u32 bitrange, struct super_block *f_sb,
	struct dentry *p_dentry, struct vfsmount *p_mnt)
{
	int len;
	char *p;
	struct path path;

	*task = kzalloc(sizeof(**task), GFP_KERNEL);
	if (!(*task))
		return -ENOMEM;

	/* Allocate temporary space for getpath file paths */
	(*task)->pathbuf = kzalloc(MAX_PATH, GFP_KERNEL);
	if (!(*task)->pathbuf) {
		printk(KERN_ERR "duet: failed to allocate pathbuf for task\n");
		kfree(*task);
		return -ENOMEM;
	}

	/* Find and store registered dir path, if applicable */
	if (!p_dentry || !p_mnt)
		goto no_reg_dir;

	(*task)->parbuf = kzalloc(MAX_PATH, GFP_KERNEL);
	if (!(*task)->parbuf) {
		printk(KERN_ERR "duet: failed to allocate parbuf for task\n");
		kfree((*task)->pathbuf);
		kfree(*task);
		return -ENOMEM;
	}

	/* Populate registered dir path buffer */
	len = MAX_PATH;
	path.mnt = p_mnt;
	path.dentry = p_dentry;

	p = d_path(&path, (*task)->pathbuf, len);
	if (IS_ERR(p)) {
		printk(KERN_ERR "duet: failed to get registered path\n");
		goto err;
	} else if (!p) {
		printk(KERN_ERR "duet: got (null) registered path\n");
		goto err;
	}

	duet_dbg(KERN_INFO "duet: got registered path %s\n", p);
	(*task)->parbuflen = len - (p - (*task)->pathbuf);
	memcpy((*task)->parbuf, p, (*task)->parbuflen);

no_reg_dir:
	(*task)->id = 1;
	memcpy((*task)->name, name, MAX_NAME);
	atomic_set(&(*task)->refcount, 0);
	INIT_LIST_HEAD(&(*task)->task_list);
	init_waitqueue_head(&(*task)->cleaner_queue);

	/* Is this a file or a block task? */
	(*task)->is_file = ((regmask & DUET_FILE_TASK) ? 1 : 0);

	/* Initialize bitmap tree */
	if (!bitrange)
		bitrange = 4096;
	bittree_init(&(*task)->bittree, bitrange, (*task)->is_file);

	/* Initialize hash table bitmap */
	spin_lock_init(&(*task)->bbmap_lock);
	(*task)->bucket_bmap = kzalloc(sizeof(unsigned long) *
		BITS_TO_LONGS(duet_env.itm_hash_size), GFP_KERNEL);
	if (!(*task)->bucket_bmap) {
		printk(KERN_ERR "duet: failed to allocate bucket bitmap\n");
		kfree((*task)->parbuf);
		kfree((*task)->pathbuf);
		kfree(*task);
		return -ENOMEM;
	}

	(*task)->bmap_cursor = 0;

	/* Do some sanity checking on event mask. */
	if (regmask & DUET_PAGE_EXISTS) {
		if (regmask & (DUET_PAGE_ADDED | DUET_PAGE_REMOVED)) {
			printk(KERN_DEBUG "duet: failed to register EXIST events\n");
			goto err;
		}
		regmask |= (DUET_PAGE_ADDED | DUET_PAGE_REMOVED);
	}

	if (regmask & DUET_PAGE_MODIFIED) {
		if (regmask & (DUET_PAGE_DIRTY | DUET_PAGE_FLUSHED)) {
			printk(KERN_DEBUG "duet: failed to register MODIFIED events\n");
			goto err;
		}
		regmask |= (DUET_PAGE_DIRTY | DUET_PAGE_FLUSHED);
	}

	(*task)->evtmask = (__u16) (regmask & 0xffff);
	(*task)->f_sb = f_sb;
	(*task)->p_dentry = p_dentry;
	(*task)->p_mnt = p_mnt;

	printk(KERN_DEBUG "duet: task %d registered %s(%d) with evtmask %x",
		(*task)->id, (*task)->parbuf, (*task)->parbuflen,
		(*task)->evtmask);
	return 0;
err:
	printk(KERN_ERR "duet: error registering task\n");
	kfree((*task)->parbuf);
	kfree((*task)->pathbuf);
	kfree(*task);
	return -EINVAL;
}

/* Properly dismantle and dispose of a task struct.
 * At this point we've guaranteed that noone else is accessing the
 * task struct, so we don't need any locks */
void duet_task_dispose(struct duet_task *task)
{
	struct duet_item itm;

	/* Dispose of the bitmap tree */
	bittree_destroy(&task->bittree);

	/* Dispose of hash table entries, bucket bitmap */
	while (!hash_fetch(task, &itm));
	kfree(task->bucket_bmap);

	if (task->p_dentry)
		dput(task->p_dentry);
	kfree(task->parbuf);
	kfree(task->pathbuf);
	kfree(task);
}

/* Registers a user-level task. Must also prep path. */
int __register_utask(char *path, __u32 regmask, __u32 bitrange,
	const char *name, __u8 *taskid)
{
	int ret;
	struct list_head *last;
	struct duet_task *cur, *task = NULL;
	struct file *file;
	mm_segment_t old_fs;
	struct dentry *dentry = NULL;
	struct vfsmount *mnt;
	struct super_block *sb;

	/* First, open the path we were given */
	old_fs = get_fs();
	set_fs(KERNEL_DS);

	file = filp_open(path, O_RDONLY, 0644);
	if (!file) {
		printk(KERN_ERR "duet_register: failed to open %s\n", path);
		ret = -EINVAL;
		goto reg_done;
	}

	if (!file->f_inode) {
		printk(KERN_ERR "duet_register: no inode for %s\n", path);
		ret = -EINVAL;
		goto reg_close;
	}

	if (!S_ISDIR(file->f_inode->i_mode)) {
		printk(KERN_ERR "duet_register: %s is not a dir\n", path);
		ret = -EINVAL;
		goto reg_close;
	}

	if (!(dentry = d_find_alias(file->f_inode))) {
		printk(KERN_ERR "duet_register: no dentry for %s\n", path);
		ret = -EINVAL;
		goto reg_close;
	}

	sb = file->f_inode->i_sb;
	mnt = file->f_path.mnt;

	if (strnlen(name, MAX_NAME) == MAX_NAME) {
		printk(KERN_ERR "duet_register: task name too long\n");
		ret = -EINVAL;
		goto reg_close;
	}

	ret = duet_task_init(&task, name, regmask, bitrange, sb, dentry, mnt);
	if (ret) {
		printk(KERN_ERR "duet_register: failed to initialize task\n");
		ret = -EINVAL;
		goto reg_close;
	}

	/*
	 * Find a free task id for the new task. Tasks are sorted by id, so that
	 * we can find the smallest free id in one traversal (look for a gap).
	 */
	mutex_lock(&duet_env.task_list_mutex);
	last = &duet_env.tasks;
	list_for_each_entry_rcu(cur, &duet_env.tasks, task_list) {
		if (cur->id == task->id)
			(task->id)++;
		else if (cur->id > task->id)
			break;

		last = &cur->task_list;
	}
	list_add_rcu(&task->task_list, last);
	mutex_unlock(&duet_env.task_list_mutex);

	/* Now that the task is receiving events, scan the page cache and
	 * populate its ItemTree. */
	scan_page_cache(task);
	*taskid = task->id;

	printk(KERN_INFO "duet: registered %s (ino %lu, sb %p)\n",
		path, file->f_inode->i_ino, sb);

reg_close:
	filp_close(file, NULL);
reg_done:
	set_fs(old_fs);
	return ret;
}

/* Registers a kernel task. No path prep required */
int __register_ktask(char *path, __u32 regmask, __u32 bitrange,
	const char *name, __u8 *taskid)
{
	int ret;
	struct list_head *last;
	struct duet_task *cur, *task = NULL;
	struct super_block *sb;

	sb = (struct super_block *)path;

	if (strnlen(name, MAX_NAME) == MAX_NAME) {
		printk(KERN_ERR "duet_register: task name too long\n");
		return -EINVAL;
	}

	ret = duet_task_init(&task, name, regmask, bitrange, sb, NULL, NULL);
	if (ret) {
		printk(KERN_ERR "duet_register: failed to initialize task\n");
		return -EINVAL;
	}

	/*
	 * Find a free task id for the new task. Tasks are sorted by id, so that
	 * we can find the smallest free id in one traversal (look for a gap).
	 */
	mutex_lock(&duet_env.task_list_mutex);
	last = &duet_env.tasks;
	list_for_each_entry_rcu(cur, &duet_env.tasks, task_list) {
		if (cur->id == task->id)
			(task->id)++;
		else if (cur->id > task->id)
			break;

		last = &cur->task_list;
	}
	list_add_rcu(&task->task_list, last);
	mutex_unlock(&duet_env.task_list_mutex);

	/* Now that the task is receiving events, scan the page cache and
	 * populate its ItemTree. */
	scan_page_cache(task);
	*taskid = task->id;

	printk(KERN_INFO "duet: registered kernel task (sb %p)\n", sb);

	return ret;
}

int duet_register(char *path, __u32 regmask, __u32 bitrange, const char *name,
	__u8 *taskid)
{
	int ret;

	/* Do some basic sanity checking */
	if (!path || !regmask || !bitrange)
		return -EINVAL;

	if (regmask & DUET_REG_SBLOCK)
		ret = __register_ktask(path, regmask, bitrange, name, taskid);
	else
		ret = __register_utask(path, regmask, bitrange, name, taskid);

	return ret;
}
EXPORT_SYMBOL_GPL(duet_register);

int duet_deregister(__u8 taskid)
{
	struct duet_task *cur;

	/* Find the task in the list, then dispose of it */
	mutex_lock(&duet_env.task_list_mutex);
	list_for_each_entry_rcu(cur, &duet_env.tasks, task_list) {
		if (cur->id == taskid) {
#ifdef CONFIG_DUET_STATS
			hash_print(cur);
			bittree_print(cur);
#endif /* CONFIG_DUET_STATS */
			list_del_rcu(&cur->task_list);
			mutex_unlock(&duet_env.task_list_mutex);

			/* Wait until everyone's done with it */
			synchronize_rcu();
			wait_event(cur->cleaner_queue,
				atomic_read(&cur->refcount) == 0);

			duet_task_dispose(cur);
			return 0;
		}
	}
	mutex_unlock(&duet_env.task_list_mutex);

	return -ENOENT;
}
EXPORT_SYMBOL_GPL(duet_deregister);
