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
 */

#include "common.h"
#include "ioctl.h"

/* Do a preorder print of the BitTree */
int duet_print_bmap(__u8 id)
{
	struct duet_task *task;

	task = duet_find_task(id);
	if (!task)
		return -ENOENT;

	if (bittree_print(task)) {
		pr_err("duet: failed to print BitTree for task #%d\n",
			task->id);
		return -1;
	}

	/* decref and wake up cleaner if needed */
	if (atomic_dec_and_test(&task->refcount))
		wake_up(&task->cleaner_queue);

	return 0;
}

/* Do a preorder print of the global hash table */
int duet_print_item(__u8 id)
{
	struct duet_task *task;

	task = duet_find_task(id);
	if (!task)
		return -ENOENT;

	hash_print(task);

	/* decref and wake up cleaner if needed */
	if (atomic_dec_and_test(&task->refcount))
		wake_up(&task->cleaner_queue);

	return 0;
}

int duet_print_list(struct duet_ioctl_status_args __user *arg)
{
	int i = 0;
	struct duet_task *cur;
	struct duet_ioctl_status_args argh, *argp;

	/* Copy in task list header (again) */
	if (copy_from_user(&argh, arg, sizeof(argh)))
		return -EFAULT;

	/* Copy in entire task list */
	argp = memdup_user(arg, sizeof(*argp) + (argh.numtasks *
				sizeof(struct duet_task_attrs)));
	if (IS_ERR(argp))
		return PTR_ERR(argp);

	/* Copy the info for the first numtasks */
	mutex_lock(&duet_env.task_list_mutex);
	list_for_each_entry(cur, &duet_env.tasks, task_list) {
		argp->tasks[i].id = cur->id;
		argp->tasks[i].fd = cur->fd;
		memcpy(argp->tasks[i].name, cur->name->name, NAME_MAX);
		argp->tasks[i].regmask = cur->evtmask;
		memcpy(argp->tasks[i].path, cur->regpathname, cur->regpathlen);
		i++;
		if (i == argp->numtasks)
			break;
	}
	mutex_unlock(&duet_env.task_list_mutex);

	/* Copy out entire task list */
	if (copy_to_user(arg, argp, sizeof(*argp) + (argp->numtasks *
			 sizeof(struct duet_task_attrs)))) {
		pr_err("duet_print_list: failed to copy out list\n");
		kfree(argp);
		return -EINVAL;
	}

	duet_dbg("duet_print_list: success sending task list\n");
	kfree(argp);
	return 0;
}
