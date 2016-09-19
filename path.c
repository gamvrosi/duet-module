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

/* Scan through the page cache for a given inode */
static int find_get_inode(struct super_block *sb, struct duet_uuid c_uuid,
	struct inode **c_inode)
{
	struct inode *inode = NULL;

	*c_inode = NULL;
	spin_lock(&sb->s_inode_list_lock);
	list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
		spin_lock(&inode->i_lock);
		if (!*c_inode && inode->i_ino == c_uuid.ino &&
		    inode->i_generation == c_uuid.gen &&
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
	char *buf, int bufsize)
{
	int len;
	char *p;
	struct path path;
	struct dentry *alias, *i_dentry = NULL;

	if (!task) {
		pr_err("do_find_path: invalid task\n");
		return -EINVAL;
	}

	if (getpath)
		buf[0] = '\0';

	/* Get the path for at least one alias of the inode */
	if (hlist_empty(&inode->i_dentry))
		return -ENOENT;

	hlist_for_each_entry(alias, &inode->i_dentry, d_u.d_alias) {
		if (IS_ROOT(alias) && (alias->d_flags & DCACHE_DISCONNECTED))
			continue;

		i_dentry = alias;

		/* Now get the path */
		len = PATH_MAX;
		memset(task->pathbuf, 0, len);
		path.mnt = task->regpath->mnt;
		path.dentry = i_dentry;

		p = d_path(&path, task->pathbuf, len);
		if (IS_ERR(p)) {
			pr_err("do_find_path: d_path failed\n");
			continue;
		} else if (!p) {
			duet_dbg("do_find_path: dentry not found\n");
			continue;
		}

		/* Is this path of interest? */
		if (memcmp(task->regpathname, p, task->regpathlen - 1)) {
			duet_dbg("do_find_path: no common ancestor\n");
			continue;
		}

		/* Got one. If it fits, return it */
		if (getpath && (bufsize < len - (p - task->pathbuf)))
			return -ENOMEM;

		duet_dbg("do_find_path: got %s\n", p);
		if (getpath)
			memcpy(buf, p, len - (p - task->pathbuf));

		return 0;
	}

	/* We only get here if we got nothing */
	return -ENOENT;
}

int duet_find_path(struct duet_task *task, struct duet_uuid uuid, int getpath,
	char *buf, int bufsize)
{
	int ret = 0;
	struct inode *ino;

	if (!task) {
		pr_err("duet_find_path: invalid task\n");
		return -EINVAL;
	}

	/* First, we need to find struct inode for child and parent */
	if (find_get_inode(task->regpath->mnt->mnt_sb, uuid, &ino)) {
		duet_dbg("duet_find_path: child inode not found\n");
		return -ENOENT;
	}

	ret = do_find_path(task, ino, getpath, buf, bufsize);

	iput(ino);
	return ret;
}
