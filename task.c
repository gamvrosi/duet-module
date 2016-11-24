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

#include <linux/poll.h>
#include <linux/anon_inodes.h>
#include "common.h"

/* putname copy from kernel */
#define __putname(name)         kmem_cache_free(names_cachep, (void *)(name))

void putname(struct filename *name)
{
	BUG_ON(name->refcnt <= 0);

	if (--name->refcnt > 0)
		return;

	if (name->name != name->iname) {
		__putname(name->name);
		kfree(name);
	} else
		__putname(name);
}

/* Copied from mm/util.c and simplified */
struct address_space *page_mapping(struct page *page)
{
	struct address_space *mapping;

	page = compound_head(page);

	/* This happens if someone calls flush_dcache_page on slab page */
	if (unlikely(PageSlab(page)) || unlikely(PageSwapCache(page)))
		return NULL;

	mapping = page->mapping;
	if ((unsigned long)mapping & PAGE_MAPPING_FLAGS)
		return NULL;
	return mapping;
}

/*
 * To synchronize access to the task list and structures without compromising
 * scalability, a two-level approach is used. At the task list level, which is
 * rarely updated, RCU is used. For the task structures, we use traditional
 * reference counting. The two techniques are interweaved to achieve overall
 * consistency.
 */

/* Find task and increment its refcount */
struct duet_task *duet_find_task(__u8 id)
{
	struct duet_task *cur, *task = NULL;

	rcu_read_lock();
	list_for_each_entry_rcu(cur, &duet_env.tasks, task_list) {
		if (cur->id == id) {
			task = cur;
			atomic_inc(&task->refcount);
			break;
		}
	}
	rcu_read_unlock();

	return task;
}

/*
 * Properly dismantle and dispose of a task struct.
 * At this point we've guaranteed that noone else is accessing the
 * task struct, so we don't need any locks
 */
void duet_task_dispose(struct duet_task *task)
{
	int ret = 0;
	struct duet_item itm;

	/* Dispose of the bitmap tree */
	bittree_destroy(&task->bittree);

	/* Dispose of hash table entries, bucket bitmap */
	while (!ret)
		ret = hash_fetch(task, &itm);
	kfree(task->bucket_bmap);

	kfree(task->name);
	path_put(task->regpath);
	kfree(task->regpath);
	kfree(task->regpathname);
	kfree(task->pathbuf);
	kfree(task);
}

static unsigned int duet_poll(struct file *file, poll_table *wait)
{
	__u8 *tid = file->private_data;
	struct duet_task *task;
	int ret = 0;

	task = duet_find_task(*tid);
	if (!task) {
		pr_err("duet_poll: task not found\n");
		return ret;
	}

	poll_wait(file, &task->event_queue, wait);
	if (bitmap_weight(task->bucket_bmap, duet_env.itm_hash_size))
		ret = POLLIN | POLLRDNORM;

	return ret;
}

/*
 * Copy an item to user space, returning how much we copied.
 *
 * We already checked that the event size is smaller than the
 * buffer we had in duet_read() below.
 */
static ssize_t copy_item_to_user(struct duet_task *task,
				 struct duet_item *item,
				 char __user *buf)
{
	size_t item_size = sizeof(struct duet_item);

	/* Send the item */
	if (copy_to_user(buf, item, item_size))
		return -EFAULT;

	buf += item_size;

	duet_dbg("duet_read: sending (ino%lu, gen%u, idx%lu, %x)\n",
		 item->uuid.ino, item->uuid.gen, item->idx, item->state);

	return item_size;
}

/*
 * Sends out duet items. The number of bytes returned corresponds to the number
 * of sizeof(struct duet_item) items fetched. Items are checked against the
 * bitmap, and discarded if they have been marked; this can happen because an
 * insertion can occur between the last read and the last bitmap set operation.
 */
static ssize_t duet_read(struct file *file, char __user *buf,
			 size_t count, loff_t *pos)
{
	struct duet_task *task;
	struct duet_item item;
	char __user *start;
	int ret, err;
	__u8 *tid;
	DEFINE_WAIT_FUNC(wait, woken_wake_function);

	start = buf;
	tid = file->private_data;

	task = duet_find_task(*tid);
	if (!task)
		return -ENOENT;

	add_wait_queue(&task->event_queue, &wait);
	while (1) {
		/* Fetch an item only if there's space to store it */
		if (sizeof(struct duet_item) > count)
			err = -EINVAL;
		else
			err = hash_fetch(task, &item);

		if (!err) {
			ret = copy_item_to_user(task, &item, buf);
			if (ret < 0)
				break;
			buf += ret;
			count -= ret;
			continue;
		}

		ret = -EAGAIN;
		if (file->f_flags & O_NONBLOCK)
			break;
		ret = -ERESTARTSYS;
		if (signal_pending(current))
			break;

		if (start != buf)
			break;

		wait_woken(&wait, TASK_INTERRUPTIBLE, MAX_SCHEDULE_TIMEOUT);
	}
	remove_wait_queue(&task->event_queue, &wait);

	if (start != buf && ret != -EFAULT)
		ret = buf - start;

	/* Decref and wake up cleaner if needed */
	if (atomic_dec_and_test(&task->refcount))
		wake_up(&task->cleaner_queue);

	return ret;
}

static int duet_release(struct inode *ignored, struct file *file)
{
	__u8 *tid = file->private_data;
	struct duet_task *cur;

	/* Find the task in the list, then dispose of it */
	mutex_lock(&duet_env.task_list_mutex);
	list_for_each_entry_rcu(cur, &duet_env.tasks, task_list) {
		if (cur->id == *tid) {
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

			pr_info("duet: deregistered task %d\n",	cur->id);

			duet_task_dispose(cur);
			kfree(tid);
			return 0;
		}
	}
	mutex_unlock(&duet_env.task_list_mutex);

	return -ENOENT;
}

static const struct file_operations duet_fops = {
	.show_fdinfo	= NULL,
	.poll		= duet_poll,
	.read		= duet_read,
	.fasync		= NULL,
	.release	= duet_release,
	.unlocked_ioctl	= NULL,
	.compat_ioctl	= NULL,
	.llseek		= noop_llseek,
};

static int process_inode(struct duet_task *task, struct inode *inode)
{
	struct radix_tree_iter iter;
	struct duet_uuid uuid;
	void **slot;
	__u16 state;

	/* Use the inode bitmap to decide whether to skip inode */
	if (bittree_check_inode(&task->bittree, task, inode) == 1)
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
			 * Shadow entry of recently evicted page, or swap entry
			 * from shmem/tmpfs. Skip over it.
			 */
			continue;
		}

		state = DUET_PAGE_ADDED;
		if (PageDirty(page))
			state |= DUET_PAGE_DIRTY;
		uuid.ino = inode->i_ino;
		uuid.gen = inode->i_generation;
		hash_add(task, uuid, page->index, state, 1);
	}
	rcu_read_unlock();

	return 0;
}

/* Scan through the page cache for events of interest to the task */
static int scan_page_cache(struct duet_task *task)
{
	struct inode *inode, *prev = NULL;
	struct super_block *sb = task->regpath->mnt->mnt_sb;

	pr_info("duet: page cache scan started\n");

	spin_lock(&sb->s_inode_list_lock);
	list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
		struct address_space *mapping = inode->i_mapping;

		spin_lock(&inode->i_lock);
		if (inode->i_state & DUET_INODE_FREEING ||
		    mapping->nrpages == 0) {
			spin_unlock(&inode->i_lock);
			continue;
		}
		atomic_inc(&inode->i_count);
		spin_unlock(&inode->i_lock);
		spin_unlock(&sb->s_inode_list_lock);

		/*
		 * We are holding a reference to inode so it won't be removed
		 * from s_inodes list while we don't hold the s_inode_list_lock.
		 * We cannot iput the inode now, though, as we may be holding
		 * the last reference. We will iput it after the iteration is
		 * done.
		 */

		iput(prev);
		prev = inode;

		process_inode(task, inode);

		spin_lock(&sb->s_inode_list_lock);
	}
	spin_unlock(&sb->s_inode_list_lock);
	iput(prev);

	pr_info("duet: page cache scan finished\n");

	return 0;
}

/* Allocate and initialize a task struct */
static int duet_task_init(struct duet_task **task, char *name, __u32 regmask,
	struct path *path)
{
	int len;
	char *p;
	u32 evtmask = regmask;

	/* Do some sanity checking on event mask. */
	if (evtmask & DUET_PAGE_EXISTS) {
		if (evtmask & (DUET_PAGE_ADDED | DUET_PAGE_REMOVED | \
		               DUET_LEVEL_ADDED)) {
			pr_debug("duet_task_init: invalid regmask\n");
			return -EINVAL;
		}
		evtmask |= (DUET_PAGE_ADDED | DUET_PAGE_REMOVED);
	}

	if (evtmask & DUET_PAGE_MODIFIED) {
		if (evtmask & (DUET_PAGE_DIRTY | DUET_PAGE_FLUSHED | \
		               DUET_LEVEL_DIRTY)) {
			pr_debug("duet_task_init: invalid regmask\n");
			return -EINVAL;
		}
		evtmask |= (DUET_PAGE_DIRTY | DUET_PAGE_FLUSHED);
	}

	if (evtmask & DUET_LEVEL_ADDED) {
		if (evtmask & (DUET_PAGE_ADDED | DUET_PAGE_REMOVED | \
		               DUET_PAGE_EXISTS)) {
			pr_debug("duet_task_init: invalid regmask\n");
			return -EINVAL;
		}
		evtmask |= (DUET_PAGE_ADDED | DUET_PAGE_REMOVED);
	}

	if (evtmask & DUET_LEVEL_DIRTY) {
		if (evtmask & (DUET_PAGE_DIRTY | DUET_PAGE_FLUSHED | \
		               DUET_PAGE_MODIFIED)) {
			pr_debug("duet_task_init: invalid regmask\n");
			return -EINVAL;
		}
		evtmask |= (DUET_PAGE_DIRTY | DUET_PAGE_FLUSHED);
	}

	/* Allocate task info struct */
	*task = kzalloc(sizeof(**task), GFP_KERNEL);
	if (!(*task))
		return -ENOMEM;

	/* Allocate temporary space for getpath file paths */
	(*task)->pathbuf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (!(*task)->pathbuf) {
		pr_err("duet_task_init: buffer allocation failed\n");
		kfree(*task);
		return -ENOMEM;
	}

	/* Find and store registered dir path */
	(*task)->regpathname = kzalloc(PATH_MAX, GFP_KERNEL);
	if (!(*task)->regpathname) {
		pr_err("duet_task_init: path allocation failed\n");
		kfree((*task)->pathbuf);
		kfree(*task);
		return -ENOMEM;
	}

	/* Populate registered dir path buffer */
	len = PATH_MAX;
	p = d_path(path, (*task)->pathbuf, len);
	if (IS_ERR(p)) {
		pr_err("duet_task_init: path registration failed\n");
		goto err;
	} else if (!p) {
		pr_err("duet_task_init: (null) registered path\n");
		goto err;
	}

	(*task)->regpathlen = len - (p - (*task)->pathbuf);
	memcpy((*task)->regpathname, p, (*task)->regpathlen);

	(*task)->id = 1;
	(*task)->name = name;
	(*task)->regpath = path;
	(*task)->evtmask = (regmask & 0xffff);
	atomic_set(&(*task)->refcount, 0);
	INIT_LIST_HEAD(&(*task)->task_list);
	init_waitqueue_head(&(*task)->cleaner_queue);
	init_waitqueue_head(&(*task)->event_queue);
	bittree_init(&(*task)->bittree);

	/* Initialize hash table bitmap */
	(*task)->bmap_cursor = 0;
	spin_lock_init(&(*task)->bbmap_lock);
	(*task)->bucket_bmap = kzalloc(sizeof(unsigned long) *
		BITS_TO_LONGS(duet_env.itm_hash_size), GFP_KERNEL);
	if (!(*task)->bucket_bmap) {
		pr_err("duet_task_init: hash bitmap alloc failed\n");
		kfree((*task)->regpathname);
		kfree((*task)->pathbuf);
		kfree(*task);
		return -ENOMEM;
	}

	return 0;
err:
	pr_err("duet_task_init: error registering task\n");
	kfree((*task)->regpathname);
	kfree((*task)->pathbuf);
	kfree(*task);
	return -EINVAL;
}

/* Register the task with Duet */
int duet_register_task(char *name, __u32 regmask, struct path *path)
{
	int ret;
	__u8 *tid;
	struct duet_task *cur, *task = NULL;
	struct list_head *last;

	/* Do some sanity checking on the parameters passed */
	if (!path || !regmask)
		return -EINVAL;

	if (!path->dentry || !path->dentry->d_inode) {
		pr_err("duet_register_task: invalid path\n");
		return -EINVAL;
	}

	if (!S_ISDIR(path->dentry->d_inode->i_mode)) {
		pr_err("duet_register_task: path is not a dir\n");
		return -EINVAL;
	}

	ret = duet_task_init(&task, name, regmask, path);
	if (ret) {
		pr_err("duet_register_task: initialization failed\n");
		return ret;
	}

	/* Now get an anonymous inode to use for communication with Duet */
	tid = kzalloc(sizeof(__u8), GFP_KERNEL);
	if (!tid) {
		duet_task_dispose(task);
		return -ENOMEM;
	}

	ret = anon_inode_getfd("duet", &duet_fops, tid,
		O_RDONLY | ((regmask & DUET_FD_NONBLOCK) ? O_NONBLOCK : 0));
	if (ret < 0) {
		duet_task_dispose(task);
		kfree(tid);
		return ret;
	}

	task->fd = ret;

	/* Find a free task id for the new task. Tasks are sorted by id. */
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

	*tid = task->id;

	/* Before we return, scan the page cache for pages of interest */
	scan_page_cache(task);

	pr_info("duet: task %d (fd %d) registered %s(%d) with mask %x\n",
		task->id, task->fd, task->regpathname, task->regpathlen,
		task->evtmask);

	return ret;
}
