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

#include <linux/namei.h>
#include <linux/tracepoint.h>
#include "ioctl.h"

int duet_online(void)
{
	return (atomic_read(&duet_env.status) == DUET_STATUS_ON);
}

static void tp_add_probe(void *data, struct page *page)
{
	pr_info("duet: tp_add_probe triggered (%lu)\n", page->index);
//	duet_hook(DUET_PAGE_ADDED, page);
}

static void tp_remove_probe(void *data, struct page *page)
{
	pr_info("duet: tp_remove_probe triggered (%lu)\n", page->index);
//	duet_hook(DUET_PAGE_REMOVED, page);
}

static void tp_dirty_probe(void *data, struct page *page)
{
	pr_info("duet: tp_dirty_probe triggered (%lu)\n", page->index);
//	duet_hook(DUET_PAGE_DIRTY, page);
}

static void tp_flush_probe(void *data, struct page *page)
{
	pr_info("duet: tp_flush_probe triggered (%lu)\n", page->index);
//	duet_hook(DUET_PAGE_FLUSHED, page);
}

static void duet_add_tracepoint(struct tracepoint *tp, void *priv)
{
	if (!strcmp(tp->name, "mm_filemap_add_to_page_cache")) {
		if (tracepoint_probe_register(tp, tp_add_probe, NULL)) {
			pr_err("duet: failed to register ADD hook\n");
		} else {
			pr_info("duet: ADD hook registered\n");
			duet_env.tpprobes |= DUET_PAGE_ADDED;
		}
	} else if (!strcmp(tp->name, "mm_filemap_delete_from_page_cache")) {
		if (tracepoint_probe_register(tp, tp_remove_probe, NULL)) {
			pr_err("duet: failed to register REMOVE hook\n");
		} else {
			pr_info("duet: REMOVE hook registered\n");
			duet_env.tpprobes |= DUET_PAGE_REMOVED;
		}
	} else if (!strcmp(tp->name, "mm_pageflags_set_page_dirty")) {
		if (tracepoint_probe_register(tp, tp_dirty_probe, NULL)) {
			pr_err("duet: failed to register DIRTY hook\n");
		} else {
			pr_info("duet: DIRTY hook registered\n");
			duet_env.tpprobes |= DUET_PAGE_DIRTY;
		}
	} else if (!strcmp(tp->name, "mm_pageflags_clear_page_dirty")) {
		if (tracepoint_probe_register(tp, tp_flush_probe, NULL)) {
			pr_err("duet: failed to register FLUSH hook\n");
		} else {
			pr_info("duet: FLUSH hook registered\n");
			duet_env.tpprobes |= DUET_PAGE_FLUSHED;
		}
	}
}

static void duet_rm_tracepoint(struct tracepoint *tp, void *priv)
{
	if (!strcmp(tp->name, "mm_filemap_add_to_page_cache")) {
		if (tracepoint_probe_unregister(tp, tp_add_probe, NULL)) {
			pr_err("duet: failed to remove ADD hook\n");
		} else {
			pr_info("duet: ADD hook removed\n");
			duet_env.tpprobes &= (~DUET_PAGE_ADDED);
		}
	} else if (!strcmp(tp->name, "mm_filemap_delete_from_page_cache")) {
		if (tracepoint_probe_unregister(tp, tp_remove_probe, NULL)) {
			pr_err("duet: failed to remove REMOVE hook\n");
		} else {
			pr_info("duet: REMOVE hook removed\n");
			duet_env.tpprobes &= (~DUET_PAGE_REMOVED);
		}
	} else if (!strcmp(tp->name, "mm_pageflags_set_page_dirty")) {
		if (tracepoint_probe_unregister(tp, tp_dirty_probe, NULL)) {
			pr_err("duet: failed to remove DIRTY hook\n");
		} else {
			pr_info("duet: DIRTY hook removed\n");
			duet_env.tpprobes &= (~DUET_PAGE_DIRTY);
		}
	} else if (!strcmp(tp->name, "mm_pageflags_clear_page_dirty")) {
		if (tracepoint_probe_register(tp, tp_flush_probe, NULL)) {
			pr_err("duet: failed to remove FLUSH hook\n");
		} else {
			pr_info("duet: FLUSH hook removed\n");
			duet_env.tpprobes &= (~DUET_PAGE_FLUSHED);
		}
	}
}

int duet_bootstrap(__u8 numtasks)
{
	int ret = 0;

	if (atomic_cmpxchg(&duet_env.status, DUET_STATUS_OFF, DUET_STATUS_INIT)
	    != DUET_STATUS_OFF) {
		pr_err("duet: framework on, bootstrap aborted\n");
		return 1;
	}

	duet_env.numtasks = (numtasks ? numtasks : DUET_DEF_NUMTASKS);

	/* Initialize global hash table */
	if (hash_init()) {
		pr_err("duet: failed to initialize hash table\n");
		return 1;
	}

	/* Initialize task list */
	INIT_LIST_HEAD(&duet_env.tasks);
	mutex_init(&duet_env.task_list_mutex);
	atomic_set(&duet_env.status, DUET_STATUS_ON);

	/* Initialize tracepoints probes */
	duet_env.tpprobes = 0;
	for_each_kernel_tracepoint(duet_add_tracepoint, NULL);
	if (((duet_env.tpprobes & DUET_COMBO_EXISTS) != DUET_COMBO_EXISTS) ||
	    ((duet_env.tpprobes & DUET_COMBO_MODIFIED) &&
	    ((duet_env.tpprobes & DUET_COMBO_MODIFIED) != DUET_COMBO_MODIFIED))) {
		pr_err("debug: Insufficient probes (%u)\n", duet_env.tpprobes);
		ret = -EINVAL;
		goto tp_fail;
	}

	return 0;

tp_fail:
	duet_shutdown();
	return (ret ? ret : 1);
}

int duet_shutdown(void)
{
	struct duet_task *task;

	if (atomic_cmpxchg(&duet_env.status, DUET_STATUS_ON, DUET_STATUS_CLEAN)
	    != DUET_STATUS_ON) {
		pr_err("duet: framework off, shutdown aborted\n");
		return 1;
	}

	/* Tear down tracepoint probes */
	for_each_kernel_tracepoint(duet_rm_tracepoint, NULL);
	tracepoint_synchronize_unregister();

	if (duet_env.tpprobes) {
		pr_err("duet: failed to remove all hooks\n");
		return -EFAULT;
	}

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

static int duet_ioctl_status(void __user *arg)
{
	int ret = 0;
	struct duet_ioctl_status_args *sa;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	sa = memdup_user(arg, sizeof(*sa));
	if (IS_ERR(sa))
		return PTR_ERR(sa);

	/* For now, we only support one struct size */
	if (sa->size != sizeof(*sa)) {
		pr_err("duet_status: invalid args struct size (%u)\n",
			sa->size);
		ret = -EINVAL;
		goto done;
	}

	/* If we're cleaning up, only allow ops that affect Duet status */
	if (atomic_read(&duet_env.status) != DUET_STATUS_ON && !(sa->flags &
	    (DUET_STATUS_START | DUET_STATUS_STOP | DUET_STATUS_REPORT))) {
		pr_err("duet_status: ops rejected during shutdown\n");
		ret = -EINVAL;
		goto done;
	}

	switch (sa->flags) {
	case DUET_STATUS_START:
		ret = duet_bootstrap(sa->maxtasks);

		if (ret)
			pr_err("duet: failed to enable framework\n");
		else
			pr_info("duet: framework enabled\n");

		break;

	case DUET_STATUS_STOP:
		ret = duet_shutdown();

		if (ret)
			pr_err("duet: failed to disable framework\n");
		else
			pr_info("duet: framework disabled\n");

		break;

	case DUET_STATUS_REPORT:
		ret = duet_online();
		break;

	case DUET_STATUS_PRINT_BMAP:
		ret = duet_print_bmap(sa->id);
		break;

	case DUET_STATUS_PRINT_ITEM:
		ret = duet_print_item(sa->id);
		break;

	case DUET_STATUS_PRINT_LIST:
		ret = duet_print_list(arg);
		goto done;

	default:
		pr_info("duet_status: invalid flags\n");
		ret = -EINVAL;
		goto done;
	}

	if (copy_to_user(arg, sa, sizeof(*sa))) {
		pr_err("duet_status: copy_to_user failed\n");
		ret = -EINVAL;
		goto done;
	}

done:
	kfree(sa);
	return ret;
}

static int duet_ioctl_init(void __user *arg)
{
	int ret;
	unsigned int lookup_flags = LOOKUP_DIRECTORY;
	struct duet_ioctl_init_args *ia;
	char *name = NULL;
	struct path *path = NULL;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (!duet_online())
		return -ESRCH;

	ia = memdup_user(arg, sizeof(*ia));
	if (IS_ERR(ia))
		return PTR_ERR(ia);

	/* For now, we only support one struct size */
	if (ia->size != sizeof(*ia)) {
		pr_err("duet_init: invalid args struct size (%u)\n", ia->size);
		kfree(ia);
		return -EINVAL;
	}

	/* Do some basic sanity checking */
	if (!ia->path || !ia->regmask)
		return -EINVAL;

	if (ia->name) {
		name = kzalloc(NAME_MAX, GFP_KERNEL);
		if (!name)
			return -ENOMEM;

		memcpy(name, ia->name, NAME_MAX);
	}

	path = kzalloc(sizeof(struct path), GFP_KERNEL);
	if (!path) {
		kfree(name);
		return -ENOMEM;
	}

	ret = kern_path(ia->path, lookup_flags, path);
	if (ret) {
		pr_err("duet_init: kern_path failed for %s\n", ia->path);
		goto err;
	}

	/* Register the task with the framework */
	ret = duet_register_task(name, ia->regmask, path);
	if (ret < 0) {
		pr_err("duet_init: task registration failed\n");
		goto err;
	}

	if (copy_to_user(arg, ia, sizeof(*ia))) {
		ret = -EFAULT;
		goto err;
	}

	kfree(ia);
	return ret;

err:
	kfree(name);
	path_put(path);
	kfree(path);
	kfree(ia);
	return ret;
}

static int duet_ioctl_bmap(void __user *arg)
{
	int ret = 0;
	struct duet_ioctl_bmap_args *ba;
	struct duet_task *task;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (!duet_online())
		return -ESRCH;

	ba = memdup_user(arg, sizeof(*ba));
	if (IS_ERR(ba))
		return PTR_ERR(ba);

	/* For now, we only support one struct size */
	if (ba->size != sizeof(*ba)) {
		pr_err("duet_bmap: invalid args struct size (%u)\n", ba->size);
		ret = -EINVAL;
		goto done;
	}

	task = duet_find_task(ba->uuid.tid);
	if (!task)
		return -ENOENT;

	switch (ba->flags) {
	case DUET_BMAP_SET:
		ret = bittree_set(&task->bittree, ba->uuid);
		break;

	case DUET_BMAP_RESET:
		ret = bittree_reset(&task->bittree, ba->uuid);
		break;

	case DUET_BMAP_CHECK:
		ret = bittree_check(&task->bittree, ba->uuid, task);
		break;

	default:
		pr_err("duet_bmap: invalid flags\n");
		ret = -EINVAL;
		break;
	}

	/* decreg and wake up cleaner if needed */
	if (atomic_dec_and_test(&task->refcount))
		wake_up(&task->cleaner_queue);

done:
	kfree(ba);
	return ret;
}

static int duet_ioctl_getpath(void __user *arg)
{
	int pathlen, ret = 0;
	struct duet_ioctl_gpath_args *ga;
	struct duet_task *task;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (!duet_online())
		return -ESRCH;

	ga = memdup_user(arg, sizeof(*ga));
	if (IS_ERR(ga))
		return PTR_ERR(ga);

	/* For now, we only support one struct size */
	if (ga->size != sizeof(*ga)) {
		pr_err("duet_get_path: invalid args struct size (%u)\n",
			ga->size);
		ret = -EINVAL;
		goto done;
	}

	/* Do some basic sanity checking */
	if (!ga->uuid.tid) {
		ret = -EINVAL;
		goto done;
	}

	task = duet_find_task(ga->uuid.tid);
	if (!task) {
		ret = -ENOENT;
		goto done;
	}

	pathlen = PATH_MAX;
	ret = duet_find_path(task, ga->uuid, 1, ga->path, pathlen);

	if (!ret && copy_to_user(arg, ga, sizeof(*ga))) {
		ret = -EFAULT;
		goto done;
	}

	/* decref and wake up cleaner if needed */
	if (atomic_dec_and_test(&task->refcount))
		wake_up(&task->cleaner_queue);

done:
	kfree(ga);
	return ret;
}

/* 
 * ioctl handler function; passes control to the proper handling function
 * for the ioctl received.
 */
long duet_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	void __user *argp = (void __user *)arg;

	/* Accept only status ioctls, unless the framework is fully on */
	if (atomic_read(&duet_env.status) != DUET_STATUS_ON &&
	    cmd != DUET_IOC_STATUS) {
		pr_info("duet: ioctl rejected because duet is offline\n");
		return -EINVAL;
	}

	/* Do some basic sanity checking */
	if (!argp)
		return -EINVAL;

	switch (cmd) {
	case DUET_IOC_STATUS:
		return duet_ioctl_status(argp);
	case DUET_IOC_INIT:
		return duet_ioctl_init(argp);
	case DUET_IOC_BMAP:
		return duet_ioctl_bmap(argp);
	case DUET_IOC_GPATH:
		return duet_ioctl_getpath(argp);
	}

	return -EINVAL;
}
