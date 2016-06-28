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

#include <linux/fs.h>
#include <linux/duet.h>
#include <linux/vmalloc.h>
#include <asm/uaccess.h>
#include "ioctl.h"

int duet_online(void)
{
	return (atomic_read(&duet_env.status) == DUET_STATUS_ON);
}
EXPORT_SYMBOL_GPL(duet_online);

int duet_bootstrap(__u8 numtasks)
{
	if (atomic_cmpxchg(&duet_env.status, DUET_STATUS_OFF, DUET_STATUS_INIT)
	    != DUET_STATUS_OFF) {
		printk(KERN_WARNING "duet: framework not off, bootstrap aborted\n");
		return 1;
	}

	duet_env.numtasks = (numtasks ? numtasks : DUET_DEF_NUMTASKS);

	/* Initialize global hash table */
	if (hash_init()) {
		printk(KERN_ERR "duet: failed to initialize hash table\n");
		return 1;
	}

	/* Initialize task list */
	INIT_LIST_HEAD(&duet_env.tasks);
	mutex_init(&duet_env.task_list_mutex);
	atomic_set(&duet_env.status, DUET_STATUS_ON);

#ifdef CONFIG_DUET_STATS
	/* Initialize stat counters */
	duet_env.itm_stat_lkp = duet_env.itm_stat_num = 0;
#endif /* CONFIG_DUET_STATS */

	rcu_assign_pointer(duet_hook_fp, duet_hook);
	synchronize_rcu();
	return 0;
}

int duet_shutdown(void)
{
	struct duet_task *task;

	if (atomic_cmpxchg(&duet_env.status, DUET_STATUS_ON, DUET_STATUS_CLEAN)
	    != DUET_STATUS_ON) {
		printk(KERN_WARNING "duet: framework off, shutdown aborted\n");
		return 1;
	}

	rcu_assign_pointer(duet_hook_fp, NULL);
	synchronize_rcu();

	/* Remove all tasks */
	mutex_lock(&duet_env.task_list_mutex);
	while (!list_empty(&duet_env.tasks)) {
		task = list_entry_rcu(duet_env.tasks.next, struct duet_task,
				task_list);
		list_del_rcu(&task->task_list);
		mutex_unlock(&duet_env.task_list_mutex);

		/* Make sure everyone's let go before we free it */
		synchronize_rcu();
		wait_event(task->cleaner_queue,
			atomic_read(&task->refcount) == 0);
		duet_task_dispose(task);

		mutex_lock(&duet_env.task_list_mutex);
	}
	mutex_unlock(&duet_env.task_list_mutex);

	/* Destroy global hash table */
	vfree((void *)duet_env.itm_hash_table);

	INIT_LIST_HEAD(&duet_env.tasks);
	mutex_destroy(&duet_env.task_list_mutex);
	atomic_set(&duet_env.status, DUET_STATUS_OFF);
	return 0;
}

/* Scan through the page cache for a given inode */
static int find_get_inode(struct super_block *sb, unsigned long long c_uuid,
	struct inode **c_inode)
{
	struct inode *inode = NULL;

	*c_inode = NULL;
	spin_lock(&sb->s_inode_list_lock);
	list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
		spin_lock(&inode->i_lock);
		if (!*c_inode && (DUET_GET_UUID(inode) == c_uuid) &&
		    !(inode->i_state & DUET_INODE_FREEING)) {
			atomic_inc(&inode->i_count);
			*c_inode = inode;
			spin_unlock(&inode->i_lock);
			spin_unlock(&sb->s_inode_list_lock);
			return 0;
		}
		spin_unlock(&inode->i_lock);
	}
	spin_unlock(&sb->s_inode_list_lock);

	/* We shouldn't get here unless we failed */
	return 1;
}

int do_find_path(struct duet_task *task, struct inode *inode, int getpath,
	char *path)
{
	int len, ret = 0;
	char *p;

	if (!task || !task->p_dentry) {
		printk(KERN_ERR "do_find_path%s: invalid task registration\n",
			(getpath ? "" : " (null)"));
		return 1;
	}

	/* Now get the path */
	len = MAX_PATH;
	ret = d_find_path(inode, task->p_dentry, getpath, task->pathbuf, len, &p);
	if (ret == 1) {
		duet_dbg(KERN_INFO "do_find_path%s: parent dentry not found\n",
				(getpath ? "" : " (null)"));
		if (getpath)
			path[0] = '\0';
	} else if (ret == -1) {
		duet_dbg(KERN_INFO "do_find_path%s: no common ancestor\n",
				(getpath ? "" : " (null)"));
		if (getpath)
			path[0] = '\0';
	} else if (getpath) {
		duet_dbg(KERN_INFO "do_find_path%s: got %s\n",
				(getpath ? "" : " (null)"), p);
		p++;
		memcpy(path, p, len - (p - task->pathbuf) + 1);
	}

	return ret;
}

int duet_find_path(struct duet_task *task, unsigned long long uuid, int getpath,
	char *path)
{
	int ret = 0;
	struct inode *ino;

	if (!task || !task->p_dentry) {
		printk(KERN_ERR "duet_find_path%s: invalid task registration\n",
			(getpath ? "" : " (null)"));
		return 1;
	}

	/* First, we need to find struct inode for child and parent */
	if (find_get_inode(task->f_sb, uuid, &ino)) {
		duet_dbg(KERN_NOTICE "duet_find_path%s: failed to find child inode\n",
			(getpath ? "" : " (null)"));
		return 1;
	}

	ret = do_find_path(task, ino, getpath, path);

	iput(ino);
	return ret;
}

static int duet_get_path(__u8 tid, __u64 c_uuid, char *cpath)
{
	int ret = 0;
	struct duet_task *task = duet_find_task(tid);

	if (!task) {
		printk(KERN_ERR "duet_get_path: invalid taskid (%d)\n", tid);
		return 1;	
	}

	ret = duet_find_path(task, (unsigned long long) c_uuid, 1, cpath);

	/* decref and wake up cleaner if needed */
	if (atomic_dec_and_test(&task->refcount))
		wake_up(&task->cleaner_queue);

	return ret;
}

static int duet_ioctl_fetch(void __user *arg)
{
	struct duet_ioctl_fetch_args argh, *argp;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	/* Copy in fetch header */
	if (copy_from_user(&argh, arg, sizeof(argh)))
		return -EFAULT;

	/* Copy in entire fetch list */
	argp = memdup_user(arg, sizeof(*argp) + (argh.num *
				sizeof(struct duet_item)));
	if (IS_ERR(argp))
		return PTR_ERR(argp);

	if (duet_fetch(argp->tid, argp->itm, &argp->num)) {
		printk(KERN_ERR "duet: failed to fetch for user\n");
		goto err;
	}

	/* Copy out entire fetch list */
	if (copy_to_user(arg, argp, sizeof(*argp) + (argp->num *
			 sizeof(struct duet_item)))) {
		printk(KERN_ERR "duet: failed to copy out args\n");
		goto err;
	}

	kfree(argp);
	return 0;

err:
	kfree(argp);
	return -EINVAL;
}

static int duet_ioctl_cmd(void __user *arg)
{
	struct duet_ioctl_cmd_args *ca;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ca = memdup_user(arg, sizeof(*ca));
	if (IS_ERR(ca))
		return PTR_ERR(ca);

	/* If we're in the process of cleaning up, no ioctls (other
	 * than the one that switches duet on/off) are allowed */
	if (atomic_read(&duet_env.status) != DUET_STATUS_ON &&
	    ca->cmd_flags != DUET_START && ca->cmd_flags != DUET_STOP) {
		printk(KERN_INFO "duet: ioctl rejected - duet is offline\n");
		goto err;
	}

	switch (ca->cmd_flags) {
	case DUET_START:
		ca->ret = duet_bootstrap(ca->numtasks);

		if (ca->ret)
			printk(KERN_ERR "duet: failed to enable framework\n");
		else
			printk(KERN_INFO "duet: framework enabled\n");

		break;

	case DUET_STOP:
		ca->ret = duet_shutdown();

		if (ca->ret)
			printk(KERN_ERR "duet: failed to disable framework\n");
		else
			printk(KERN_INFO "duet: framework disabled\n");

		break;

	case DUET_REGISTER:
		ca->ret = duet_register(ca->path, ca->regmask, ca->bitrange,
					ca->name, &ca->tid);
		break;

	case DUET_DEREGISTER:
		ca->ret = duet_deregister(ca->tid);
		break;

	case DUET_SET_DONE:
		ca->ret = duet_set_done(ca->tid, ca->itmidx, ca->itmnum);
		break;

	case DUET_UNSET_DONE:
		ca->ret = duet_unset_done(ca->tid, ca->itmidx, ca->itmnum);
		break;

	case DUET_CHECK_DONE:
		ca->ret = duet_check_done(ca->tid, ca->itmidx, ca->itmnum);
		break;

	case DUET_PRINTBIT:
		ca->ret = duet_print_bitmap(ca->tid);
		break;

	case DUET_PRINTITEM:
		ca->ret = duet_print_events(ca->tid);
		break;

	case DUET_GET_PATH:
		ca->ret = duet_get_path(ca->tid, ca->c_uuid, ca->cpath);
		break;

	default:
		printk(KERN_INFO "duet: unknown tasks command received\n");
		goto err;
		break;
	}

	if (copy_to_user(arg, ca, sizeof(*ca))) {
		printk(KERN_ERR "duet: failed to copy out args\n");
		goto err;
	}

	kfree(ca);
	return 0;

err:
	kfree(ca);
	return -EINVAL;
}

static int duet_ioctl_tlist(void __user *arg)
{
	int i=0;
	struct duet_task *cur;
	struct duet_ioctl_list_args argh, *argp;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	/* Copy in task list header */
	if (copy_from_user(&argh, arg, sizeof(argh)))
		return -EFAULT;

	/* Copy in entire task list */
	argp = memdup_user(arg, sizeof(*argp) + (argh.numtasks *
				sizeof(struct duet_task_attrs)));
	if (IS_ERR(argp))
		return PTR_ERR(argp);
	
	/* We will only send the first numtasks, and that's ok */
	mutex_lock(&duet_env.task_list_mutex);
	list_for_each_entry(cur, &duet_env.tasks, task_list) {
		argp->tasks[i].tid = cur->id;
		memcpy(argp->tasks[i].tname, cur->name, MAX_NAME);
		argp->tasks[i].is_file = cur->is_file;
		argp->tasks[i].bitrange = cur->bittree.range;
		argp->tasks[i].evtmask = cur->evtmask;
		i++;
		if (i == argp->numtasks)
			break;
        }
	mutex_unlock(&duet_env.task_list_mutex);

	/* Copy out entire task list */
	if (copy_to_user(arg, argp, sizeof(*argp) + (argp->numtasks *
			 sizeof(struct duet_task_attrs)))) {
		printk(KERN_ERR "duet: failed to copy out task list items\n");
		kfree(argp);
		return -EINVAL;
	}

	duet_dbg(KERN_INFO "duet: task list sent\n");
	kfree(argp);
	return 0;
}

/* 
 * ioctl handler function; passes control to the proper handling function
 * for the ioctl received.
 */
long duet_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	void __user *argp = (void __user *)arg;

	/* If we're in the process of cleaning up, no ioctls (other
	 * than the one that switches duet on/off) are allowed */
	if (atomic_read(&duet_env.status) != DUET_STATUS_ON &&
	    cmd != DUET_IOC_CMD) {
		printk(KERN_INFO "duet: ioctl rejected - duet is offline\n");
		return -EINVAL;
	}

	switch (cmd) {
	case DUET_IOC_CMD:
		return duet_ioctl_cmd(argp);
	case DUET_IOC_TLIST:
		return duet_ioctl_tlist(argp);
	case DUET_IOC_FETCH:
		return duet_ioctl_fetch(argp);
	}

	return -EINVAL;
}
