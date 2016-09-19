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

#include "common.h"

/* Handle an event. We're in RCU context so whatever happens, stay awake! */
void duet_hook(__u16 evtcode, void *data)
{
	struct page *page = NULL;
	struct inode *inode = NULL;
	struct duet_task *cur;
	unsigned long page_idx = 0;
	struct duet_uuid uuid;

	/* Duet must be online */
	if (!duet_online())
		return;

	/* Handle page event */
	page = (struct page *)data;

	/* Duet must be online, and the page must belong to a valid mapping */
	if (!page || !page_mapping(page)) {
		duet_dbg("duet: dropped event %x due to NULL mapping\n",
			evtcode);
		return;
	}

	inode = page_mapping(page)->host;
	page_idx = page->index;

	/* Check that we're referring to an actual inode and get its UUID */
	if (!inode)
		return;

	uuid.ino = inode->i_ino;
	uuid.gen = inode->i_generation;

	/* Verify that the inode does not belong to a special file */
	if (!S_ISREG(inode->i_mode) && !S_ISDIR(inode->i_mode))
		return;

	if (!inode->i_ino) {
		pr_err("duet: inode not initialized\n");
		return;
	}

	/* Look for tasks interested in this event type and invoke callbacks */
	rcu_read_lock();
	list_for_each_entry_rcu(cur, &duet_env.tasks, task_list) {
		struct super_block *sb = cur->regpath->mnt->mnt_sb;

		/* Verify that the event refers to the fs we're interested in */
		if (sb && sb != inode->i_sb)
			continue;

		duet_dbg("duet: rcvd event %x on (ino %lu, gen %u, idx %lu)\n",
			evtcode, uuid.ino, uuid.gen, page_idx);

		/* Use the inode bitmap to filter out event if applicable */
		if (bittree_check_inode(&cur->bittree, cur, inode) == 1)
			continue;

		/* Update the hash table */
		if (hash_add(cur, uuid, page_idx, evtcode, 0))
			pr_err("duet: hash table add failed\n");

		wake_up(&cur->event_queue);
	}
	rcu_read_unlock();
}
