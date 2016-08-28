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

#define BMAP_READ	0x01	/* Read bmaps (overrides other flags) */
#define BMAP_CHECK	0x02	/* Check given bmap value expression */
				/* Sets bmaps to match expression if not set */

/* Bmap expressions can be formed using the following flags: */
#define BMAP_DONE_SET	0x04	/* Set done bmap values */
#define BMAP_DONE_RST	0x08	/* Reset done bmap values */
#define BMAP_RELV_SET	0x10	/* Set relevant bmap values */
#define BMAP_RELV_RST	0x20	/* Reset relevant bmap values */
#define BMAP_SEEN_SET	0x40	/* Set seen bmap values */
#define BMAP_SEEN_RST	0x80	/* Reset seen bmap values */

/* Some macros to make our life easier */
#define BMAP_ALL_SET	(BMAP_SEEN_SET | BMAP_RELV_SET | BMAP_DONE_SET)
#define BMAP_ALL_RST	(BMAP_SEEN_RST | BMAP_RELV_RST | BMAP_DONE_RST)

#define BITTREE_RANGE	PAGE_SIZE	/* Bytes per bitmap bit */
#define BITS_PER_NODE	(32768 * 8)	/* 32KB bitmaps */

#define UUID_IDX(uuid)	(((unsigned long long) uuid.gen << 32) | \
			  (unsigned long long) uuid.ino)

/*
 * The following functions are wrappers for the basic bitmap functions.
 * A bitmap is characterized by a starting offset (start). The wrappers
 * translate an arbitrary idx to the appropriate bit.
 */

/* Sets (or resets) a single bit */
static int bmap_set(unsigned long *bmap, __u64 start, __u64 idx, __u8 do_set)
{
	__u64 bofft = idx - start;

	if (bofft + 1 >= start + (BITS_PER_NODE * BITTREE_RANGE))
		return -1;

	/* Convert range to bitmap granularity */
	do_div(bofft, BITTREE_RANGE);

	if (do_set)
		bitmap_set(bmap, (unsigned int)bofft, 1);
	else
		bitmap_clear(bmap, (unsigned int)bofft, 1);

	return 0;
}

/* Returns value of bit at idx */
static int bmap_read(unsigned long *bmap, __u64 start, __u64 idx)
{
	__u64 bofft64 = idx - start;
	unsigned long *p, mask;
	unsigned int bofft;

	if (bofft64 + 1 >= start + (BITS_PER_NODE * BITTREE_RANGE))
		return -1;

	/* Convert offset to bitmap granularity */
	do_div(bofft64, BITTREE_RANGE);
	bofft = (unsigned int)bofft64;

	/* Check the bits */
	p = bmap + BIT_WORD(bofft);
	mask = BITMAP_FIRST_WORD_MASK(bofft) & BITMAP_LAST_WORD_MASK(bofft + 1);

	if ((*p) & mask)
		return 1;

	return 0;
}

/* Checks whether a bit is set */
static int bmap_chk(unsigned long *bmap, __u64 start, __u64 idx, __u8 do_set)
{
	__u64 bofft64 = idx - start;
	unsigned long *p, mask;
	unsigned int bofft;

	if (bofft64 + 1 >= start + (BITS_PER_NODE * BITTREE_RANGE))
		return -1;

	/* Convert range to bitmap granularity */
	do_div(bofft64, BITTREE_RANGE);

	/* Now it is safe to cast these variables */
	bofft = (unsigned int)bofft64;

	/* Check the bit */
	p = bmap + BIT_WORD(bofft);
	mask = BITMAP_FIRST_WORD_MASK(bofft) & BITMAP_LAST_WORD_MASK(bofft + 1);

	if (do_set && !((*p) & mask))
		return 0;
	else if (!do_set && !(~(*p) & mask))
		return 0;

	return 1;
}

/* Initializes a bitmap tree node */
static struct bmap_rbnode *bnode_init(struct duet_bittree *bt, __u64 idx)
{
	struct bmap_rbnode *bnode = NULL;

#ifdef CONFIG_DUET_STATS
	if (bt) {
		(bt->statcur)++;
		if (bt->statcur > bt->statmax) {
			bt->statmax = bt->statcur;
			pr_info("duet: %llu BitTree nodes (%llub)\n",
				bt->statmax, bt->statmax * BITS_PER_NODE / 8);
		}
	}
#endif /* CONFIG_DUET_STATS */
	
	bnode = kmalloc(sizeof(*bnode), GFP_NOWAIT);
	if (!bnode)
		return NULL;

	bnode->done = kzalloc(sizeof(unsigned long) *
			BITS_TO_LONGS(BITS_PER_NODE), GFP_NOWAIT);
	if (!bnode->done) {
		kfree(bnode);
		return NULL;
	}

	/* Allocate relevant bitmap, if needed */
	bnode->relv = kzalloc(sizeof(unsigned long) *
		BITS_TO_LONGS(BITS_PER_NODE), GFP_NOWAIT);
	if (!bnode->relv) {
		kfree(bnode->done);
		kfree(bnode);
		return NULL;
	}

	bnode->seen = kzalloc(sizeof(unsigned long) *
		BITS_TO_LONGS(BITS_PER_NODE), GFP_NOWAIT);
	if (!bnode->seen) {
		kfree(bnode->relv);
		kfree(bnode->done);
		kfree(bnode);
		return NULL;
	}

	RB_CLEAR_NODE(&bnode->node);
	bnode->idx = idx;
	return bnode;
}

static void bnode_dispose(struct bmap_rbnode *bnode, struct rb_node *rbnode,
	struct duet_bittree *bt)
{
#ifdef CONFIG_DUET_STATS
	if (bt)
		(bt->statcur)--;
#endif /* CONFIG_DUET_STATS */
	rb_erase(rbnode, &bt->root);
	kfree(bnode->relv);
	kfree(bnode->seen);
	kfree(bnode->done);
	kfree(bnode);
}

/*
 * Traverses bitmap nodes to read/set/unset/check a specific bit across bitmaps.
 * May insert/remove bitmap nodes as needed.
 *
 * If DUET_BMAP_READ is set:
 * - the bitmap value for idx are read for one or all bitmaps
 * Otherwise, if DUET_BMAP_CHECK flag is set:
 * - return value 1 means the idx matches the given flags
 * - return value 0 means the idx doesn't match the given flags
 * Otherwise, if neither flag is set:
 * - return value 0 means the idx was updated to match given flags
 *
 * In all cases, a return value -1 denotes an error.
 */
static int __update_tree(struct duet_bittree *bt, __u64 idx, __u8 flags)
{
	int found, ret, res;
	__u64 node_offt, div_rem;
	struct rb_node **link, *parent;
	struct bmap_rbnode *bnode = NULL;
	unsigned long iflags;

	local_irq_save(iflags);
	spin_lock(&bt->lock);

	div64_u64_rem(idx, BITTREE_RANGE * BITS_PER_NODE, &div_rem);
	node_offt = idx - div_rem;

	/* Look up BitTree node */
	found = 0;
	link = &(bt->root).rb_node;
	parent = NULL;

	while (*link) {
		parent = *link;
		bnode = rb_entry(parent, struct bmap_rbnode, node);

		if (bnode->idx > node_offt) {
			link = &(*link)->rb_left;
		} else if (bnode->idx < node_offt) {
			link = &(*link)->rb_right;
		} else {
			found = 1;
			break;
		}
	}

	/* If we're just reading bitmap values, return them now */
	if (flags & BMAP_READ) {
		ret = 0;

		if (!found)
			goto done;

		/* First read seen bit */
		res = bmap_read(bnode->seen, bnode->idx, idx);
		if (res == -1) {
			ret = -1;
			goto done;
		}
		ret |= res << 2;

		/* Then read relevant bit */
		res = bmap_read(bnode->relv, bnode->idx, idx);
		if (res == -1) {
			ret = -1;
			goto done;
		}
		ret |= res << 1;

		/* Read done bit */
		res = bmap_read(bnode->done, bnode->idx, idx);
		if (res == -1) {
			ret = -1;
			goto done;
		}

		ret |= res;
		goto done;
	}

	/*
	 * Take appropriate action based on whether we found the node
	 * and whether we plan to update (SET/RST), or only CHECK it.
	 *
	 *   NULL  |       Found            !Found      |
	 *  -------+------------------------------------+
	 *    SET  |     Set Bits     |  Init new node  |
	 *         |------------------+-----------------|
	 *    RST  | Clear (dispose?) |     Nothing     |
	 *  -------+------------------------------------+
	 *
	 *  CHECK  |       Found            !Found      |
	 *  -------+------------------------------------+
	 *    SET  |    Check Bits    |  Return false   |
	 *         |------------------+-----------------|
	 *    RST  |    Check Bits    |    Continue     |
	 *  -------+------------------------------------+
	 */

	/* First handle setting (or checking set) bits */
	if (flags & BMAP_ALL_SET) {
		if (!found && !(flags & BMAP_CHECK)) {
			/* Insert the new node */
			bnode = bnode_init(bt, node_offt);
			if (!bnode) {
				ret = -1;
				goto done;
			}

			rb_link_node(&bnode->node, parent, link);
			rb_insert_color(&bnode->node, &bt->root);

		} else if (!found && (flags & BMAP_CHECK)) {
			/* Looking for set bits, node didn't exist */
			ret = 0;
			goto done;
		}

		/* Set the bits. Return -1 if something goes wrong. */
		if (!(flags & BMAP_CHECK)) {
			if ((flags & BMAP_SEEN_SET) &&
			    bmap_set(bnode->seen, bnode->idx, idx, 1)) {
				ret = -1;
				goto done;
			}

			if ((flags & BMAP_RELV_SET) &&
			    bmap_set(bnode->relv, bnode->idx, idx, 1)) {
				ret = -1;
				goto done;
			}

			if ((flags & BMAP_DONE_SET) &&
			    bmap_set(bnode->done, bnode->idx, idx, 1)) {
				ret = -1;
				goto done;
			}

		/* Check the bits. Return if any bits are off */
		} else {
		if (flags & BMAP_SEEN_SET) {
				ret = bmap_chk(bnode->seen, bnode->idx, idx, 1);
				if (ret != 1)
					goto done;
			}

			if (flags & BMAP_RELV_SET) {
				ret = bmap_chk(bnode->relv, bnode->idx, idx, 1);
				if (ret != 1)
					goto done;
			}

			ret = bmap_chk(bnode->done, bnode->idx, idx, 1);
			if (ret != 1)
				goto done;
		}
	}

	/* Now handle unsetting any bits */
	if (found && (flags & BMAP_ALL_RST)) {
		/* Clear the bits. Return -1 if something goes wrong. */
		if (!(flags & BMAP_CHECK)) {
			if ((flags & BMAP_SEEN_RST) &&
			    bmap_set(bnode->seen, bnode->idx, idx, 0)) {
				ret = -1;
				goto done;
			}

			if ((flags & BMAP_RELV_RST) &&
			    bmap_set(bnode->relv, bnode->idx, idx, 0)) {
				ret = -1;
				goto done;
			}

			if ((flags & BMAP_DONE_RST) &&
			    bmap_set(bnode->done, bnode->idx, idx, 0)) {
				ret = -1;
				goto done;
			}

		/* Check the bits. Return if any bits are off */
		} else {
			if (flags & BMAP_SEEN_RST) {
				ret = bmap_chk(bnode->seen, bnode->idx, idx, 0);
				if (ret != 1)
					goto done;
			}

			if (flags & BMAP_RELV_RST) {
				ret = bmap_chk(bnode->relv, bnode->idx, idx, 0);
				if (ret != 1)
					goto done;
			}

			ret = bmap_chk(bnode->done, bnode->idx, idx, 0);
			if (ret != 1)
				goto done;
		}

		/* Dispose of the node if empty */
		if (!(flags & BMAP_CHECK) &&
		    bitmap_empty(bnode->done, BITS_PER_NODE) &&
		    bitmap_empty(bnode->seen, BITS_PER_NODE) &&
		    bitmap_empty(bnode->relv, BITS_PER_NODE))
			bnode_dispose(bnode, parent, bt);
	}

	if (!(flags & BMAP_CHECK))
		ret = 0;
	else
		ret = 1;

done:
	if (ret == -1)
		pr_err("duet: blocks were not %s\n",
			(flags & BMAP_READ) ? "read" :
			((flags & BMAP_CHECK) ? "checked" : "modified"));
	spin_unlock(&bt->lock);
	local_irq_restore(iflags);
	return ret;
}

/*
 * Check if we have seen this inode before. If not, check if it is relevant.
 * Then, check whether it's done.
 */
static int do_bittree_check(struct duet_bittree *bt, struct duet_uuid uuid,
			    struct duet_task *task, struct inode *inode)
{
	int ret, bits;
	unsigned long long idx = UUID_IDX(uuid);

	bits = __update_tree(bt, idx, BMAP_READ);

	if (!(bits & 0x4)) {
		/* We have not seen this inode before */
		if (inode) {
			ret = do_find_path(task, inode, 0, NULL, 0);
		} else if (task) {
			ret = duet_find_path(task, uuid, 0, NULL, 0);
		} else {
			pr_err("duet: check failed, no task/inode\n");
			return -1;
		}

		if (!ret) {
			/* Mark as relevant and return not done */
			ret = __update_tree(bt, idx,
					    BMAP_SEEN_SET | BMAP_RELV_SET);
			if (ret != -1)
				ret = 0;

		} else if (ret == -ENOENT) {
			/* Mark as irrelevant and return done */
			ret = __update_tree(bt, idx, BMAP_SEEN_SET);
			if (ret != -1)
				ret = 1;

		} else {
			pr_err("duet: inode relevance undetermined\n");
			return -1;
		}

	} else {
		/* We know this inode, return 1 if done, or irrelevant */
		ret = ((bits & 0x1) || !(bits & 0x2)) ? 1 : 0;
	}

	return ret;
}

/* Checks if a given inode is done. Skips inode lookup. */
int bittree_check_inode(struct duet_bittree *bt, struct duet_task *task,
	struct inode *inode)
{
	struct duet_uuid uuid;

	uuid.ino = inode->i_ino;
	uuid.gen = inode->i_generation;

	return do_bittree_check(bt, uuid, task, inode);
}

/* Checks if the given entries are done */
int bittree_check(struct duet_bittree *bt, struct duet_uuid uuid,
		  struct duet_task *task)
{
	return do_bittree_check(bt, uuid, task, NULL);
}

/* Mark done bit for given entries */
int bittree_set(struct duet_bittree *bt, struct duet_uuid uuid)
{
	return __update_tree(bt, UUID_IDX(uuid), BMAP_DONE_SET);
}

/* Unmark done bit for given entries */
int bittree_reset(struct duet_bittree *bt, struct duet_uuid uuid)
{
	return __update_tree(bt, UUID_IDX(uuid), BMAP_DONE_RST);
}

int bittree_print(struct duet_task *task)
{
	struct bmap_rbnode *bnode = NULL;
	struct rb_node *node;
	unsigned long iflags;

	local_irq_save(iflags);
	spin_lock(&task->bittree.lock);
	pr_info("duet: Printing task bittree\n");
	node = rb_first(&task->bittree.root);
	while (node) {
		bnode = rb_entry(node, struct bmap_rbnode, node);

		/* Print node information */
		pr_info("duet: Node key = %llu\n", bnode->idx);
		pr_info("duet:   Done bits set: %d out of %d\n",
			bitmap_weight(bnode->done, BITS_PER_NODE),
			BITS_PER_NODE);
		pr_info("duet:   Relv bits set: %d out of %d\n",
			bitmap_weight(bnode->relv, BITS_PER_NODE),
			BITS_PER_NODE);
		pr_info("duet:   Seen bits set: %d out of %d\n",
			bitmap_weight(bnode->seen, BITS_PER_NODE),
			BITS_PER_NODE);

		node = rb_next(node);
	}
	spin_unlock(&task->bittree.lock);
	local_irq_restore(iflags);

	pr_info("duet: Task #%d bitmap has %d out of %lu bits set\n",
		task->id, bitmap_weight(task->bucket_bmap,
		duet_env.itm_hash_size), duet_env.itm_hash_size);

	return 0;
}

void bittree_init(struct duet_bittree *bittree)
{
	spin_lock_init(&bittree->lock);
	bittree->root = RB_ROOT;
#ifdef CONFIG_DUET_STATS
	bittree->statcur = bittree->statmax = 0;
#endif /* CONFIG_DUET_STATS */
}

void bittree_destroy(struct duet_bittree *bittree)
{
	struct rb_node *rbnode;
	struct bmap_rbnode *bnode;

	while (!RB_EMPTY_ROOT(&bittree->root)) {
		rbnode = rb_first(&bittree->root);
		bnode = rb_entry(rbnode, struct bmap_rbnode, node);
		bnode_dispose(bnode, rbnode, bittree);
	}
}
