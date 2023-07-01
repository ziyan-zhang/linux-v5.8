// SPDX-License-Identifier: GPL-2.0+
/*
 * linux/fs/jbd2/transaction.c
 *
 * Written by Stephen C. Tweedie <sct@redhat.com>, 1998
 *
 * Copyright 1998 Red Hat corp --- All Rights Reserved
 *
 * Generic filesystem transaction handling code; part of the ext2fs
 * journaling system.
 *
 * This file manages transactions (compound commits managed by the
 * journaling code) and handles (individual atomic operations by the
 * filesystem).
 */

#include <linux/time.h>
#include <linux/fs.h>
#include <linux/jbd2.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/hrtimer.h>
#include <linux/backing-dev.h>
#include <linux/bug.h>
#include <linux/module.h>
#include <linux/sched/mm.h>

#include <trace/events/jbd2.h>

static void __jbd2_journal_temp_unlink_buffer(struct journal_head *jh);
static void __jbd2_journal_unfile_buffer(struct journal_head *jh);

static struct kmem_cache *transaction_cache;
int __init jbd2_journal_init_transaction_cache(void)
{
	J_ASSERT(!transaction_cache);
	transaction_cache = kmem_cache_create("jbd2_transaction_s",
					sizeof(transaction_t),
					0,
					SLAB_HWCACHE_ALIGN|SLAB_TEMPORARY,
					NULL);
	if (!transaction_cache) {
		pr_emerg("JBD2: failed to create transaction cache\n");
		return -ENOMEM;
	}
	return 0;
}

void jbd2_journal_destroy_transaction_cache(void)
{
	kmem_cache_destroy(transaction_cache);
	transaction_cache = NULL;
}

void jbd2_journal_free_transaction(transaction_t *transaction)
{
	if (unlikely(ZERO_OR_NULL_PTR(transaction)))
		return;
	kmem_cache_free(transaction_cache, transaction);
}

/*
 * Base amount of descriptor blocks we reserve for each transaction.
 */
static int jbd2_descriptor_blocks_per_trans(journal_t *journal)
{
	int tag_space = journal->j_blocksize - sizeof(journal_header_t);
	int tags_per_block;

	/* Subtract UUID */
	tag_space -= 16;
	if (jbd2_journal_has_csum_v2or3(journal))
		tag_space -= sizeof(struct jbd2_journal_block_tail);
	/* Commit code leaves a slack space of 16 bytes at the end of block */
	tags_per_block = (tag_space - 16) / journal_tag_bytes(journal);
	/*
	 * Revoke descriptors are accounted separately so we need to reserve
	 * space for commit block and normal transaction descriptor blocks.
	 */
	return 1 + DIV_ROUND_UP(journal->j_max_transaction_buffers,
				tags_per_block);
}

/*
 * jbd2_get_transaction: obtain a new transaction_t object.
 *
 * Simply initialise a new transaction. Initialize it in
 * RUNNING state and add it to the current journal (which should not
 * have an existing running transaction: we only make a new transaction
 * once we have started to commit the old one).
 *
 * 获得一个新的transaction_t对象
 * 
 * 只是初始化一个新的事务。在RUNNING状态初始化，并将其添加到当前的journal里（
 * 当前journal不应该有一个running事务存在：我们仅当开始提交旧事务时才创建一个新事务）
 * 
 * Preconditions:
 *	The journal MUST be locked.  We don't perform atomic mallocs on the
 *	new transaction	and we can't block without protecting against other
 *	processes trying to touch the journal while it is in transition.
 *
 */

static void jbd2_get_transaction(journal_t *journal,
				transaction_t *transaction)
{
	transaction->t_journal = journal;
	transaction->t_state = T_RUNNING;
	transaction->t_start_time = ktime_get();
	transaction->t_tid = journal->j_transaction_sequence++;
	transaction->t_expires = jiffies + journal->j_commit_interval;
	atomic_set(&transaction->t_updates, 0);
	atomic_set(&transaction->t_outstanding_credits,
		   jbd2_descriptor_blocks_per_trans(journal) +
		   atomic_read(&journal->j_reserved_credits));
	atomic_set(&transaction->t_outstanding_revokes, 0);
	atomic_set(&transaction->t_handle_count, 0);
	INIT_LIST_HEAD(&transaction->t_inode_list);
	INIT_LIST_HEAD(&transaction->t_private_list);

	/* Set up the commit timer for the new transaction. */
	journal->j_commit_timer.expires = round_jiffies_up(transaction->t_expires);
	add_timer(&journal->j_commit_timer);

	J_ASSERT(journal->j_running_transaction == NULL);
	journal->j_running_transaction = transaction;
	transaction->t_max_wait = 0;
	transaction->t_start = jiffies;
	transaction->t_requested = 0;
}

/*
 * Handle management.
 *
 * A handle_t is an object which represents a single atomic update to a
 * filesystem, and which tracks all of the modifications which form part
 * of that one update.
 * 
 * handle_t是一个对象，它代表一个文件系统的单个原子更新，并跟踪所有组成该更新的修改。
 */

/*
 * Update transaction's maximum wait time, if debugging is enabled.
 *
 * t_max_wait is carefully updated here with use of atomic compare exchange.
 * Note that there could be multiplre threads trying to do this simultaneously
 * hence using cmpxchg to avoid any use of locks in this case.
 * With this t_max_wait can be updated w/o enabling jbd2_journal_enable_debug.
 */
static inline void update_t_max_wait(transaction_t *transaction,
				     unsigned long ts)
{
	unsigned long oldts, newts;

	if (time_after(transaction->t_start, ts)) {
		newts = jbd2_time_diff(ts, transaction->t_start);
		oldts = READ_ONCE(transaction->t_max_wait);
		while (oldts < newts)
			oldts = cmpxchg(&transaction->t_max_wait, oldts, newts);
	}
}

/*
 * Wait until running transaction passes to T_FLUSH state and new transaction
 * can thus be started. Also starts the commit if needed. The function expects
 * running transaction to exist and releases j_state_lock.
 * 
 * 等待直到running事务转换到T_FLUSH状态，因此可以启动新事务。如果需要，也会启动提交。
 * 该函数期望running事务存在，并释放j_state_lock。
 */
static void wait_transaction_locked(journal_t *journal)
	__releases(journal->j_state_lock)
{
	DEFINE_WAIT(wait);
	int need_to_start;
	tid_t tid = journal->j_running_transaction->t_tid;

	prepare_to_wait_exclusive(&journal->j_wait_transaction_locked, &wait,
			TASK_UNINTERRUPTIBLE);
	need_to_start = !tid_geq(journal->j_commit_request, tid);
	read_unlock(&journal->j_state_lock);
	if (need_to_start)
		jbd2_log_start_commit(journal, tid);
	jbd2_might_wait_for_commit(journal);
	schedule();
	finish_wait(&journal->j_wait_transaction_locked, &wait);
}

/*
 * Wait until running transaction transitions from T_SWITCH to T_FLUSH
 * state and new transaction can thus be started. The function releases
 * j_state_lock.
 * 
 * 等待直到running事务从T_SWITCH转换到T_FLUSH状态，因此可以启动新事务。
 * 该函数释放j_state_lock。
 */
static void wait_transaction_switching(journal_t *journal)
	__releases(journal->j_state_lock)
{
	DEFINE_WAIT(wait);

	if (WARN_ON(!journal->j_running_transaction ||
		    journal->j_running_transaction->t_state != T_SWITCH)) {
		read_unlock(&journal->j_state_lock);
		return;
	}
	prepare_to_wait_exclusive(&journal->j_wait_transaction_locked, &wait,
			TASK_UNINTERRUPTIBLE);
	read_unlock(&journal->j_state_lock);
	/*
	 * We don't call jbd2_might_wait_for_commit() here as there's no
	 * waiting for outstanding handles happening anymore in T_SWITCH state
	 * and handling of reserved handles actually relies on that for
	 * correctness.
	 * 
	 * 我们不在这里调用jbd2_might_wait_for_commit()，因为在T_SWITCH状态下不再等待
	 * 未完成的句柄，并且保留句柄的处理实际上依赖于此以确保正确性。
	 */
	schedule();
	finish_wait(&journal->j_wait_transaction_locked, &wait);
}

static void sub_reserved_credits(journal_t *journal, int blocks)
{
	atomic_sub(blocks, &journal->j_reserved_credits);
	wake_up(&journal->j_wait_reserved);
}

/*
 * Wait until we can add credits for handle to the running transaction.  Called
 * with j_state_lock held for reading. Returns 0 if handle joined the running
 * transaction. Returns 1 if we had to wait, j_state_lock is dropped, and
 * caller must retry.
 *
 * Note: because j_state_lock may be dropped depending on the return
 * value, we need to fake out sparse so ti doesn't complain about a
 * locking imbalance.  Callers of add_transaction_credits will need to
 * make a similar accomodation.
 * 
 * 等待直到我们可以为句柄添加信用到正在运行的事务。在持有j_state_lock进行读取的情况下调用。
 * 如果句柄加入了正在运行的事务，则返回0。如果我们必须等待，则返回1，j_state_lock被释放，
 * 调用者必须重试。
 * 
 * 注意：因为根据返回值，j_state_lock可能会被丢弃，所以我们需要欺骗稀疏，所以它不会抱怨锁
 * 不平衡，add_transaction_credits的调用者需要做出类似的调整。
 */
static int add_transaction_credits(journal_t *journal, int blocks,
				   int rsv_blocks)
__must_hold(&journal->j_state_lock)
{
	transaction_t *t = journal->j_running_transaction;
	int needed;
	int total = blocks + rsv_blocks;

	/*
	 * If the current transaction is locked down for commit, wait
	 * for the lock to be released.
	 */
	if (t->t_state != T_RUNNING) {
		WARN_ON_ONCE(t->t_state >= T_FLUSH);
		wait_transaction_locked(journal);
		__acquire(&journal->j_state_lock); /* fake out sparse */
		return 1;
	}

	/*
	 * If there is not enough space left in the log to write all
	 * potential buffers requested by this operation, we need to
	 * stall pending a log checkpoint to free some more log space.
	 * 
	 * 如果日志中剩余的空间不足以写入此操作请求的所有潜在缓冲区，则需要暂停等待日志检查点以
	 * 释放更多日志空间。
	 */
	needed = atomic_add_return(total, &t->t_outstanding_credits);
	if (needed > journal->j_max_transaction_buffers) {
		/*
		 * If the current transaction is already too large,
		 * then start to commit it: we can then go back and
		 * attach this handle to a new transaction.
		 */
		atomic_sub(total, &t->t_outstanding_credits);

		/*
		 * Is the number of reserved credits in the current transaction too
		 * big to fit this handle? Wait until reserved credits are freed.
		 */
		if (atomic_read(&journal->j_reserved_credits) + total >
		    journal->j_max_transaction_buffers) {
			read_unlock(&journal->j_state_lock);
			jbd2_might_wait_for_commit(journal);
			wait_event(journal->j_wait_reserved,
				   atomic_read(&journal->j_reserved_credits) + total <=
				   journal->j_max_transaction_buffers);
			__acquire(&journal->j_state_lock); /* fake out sparse */
			return 1;
		}

		wait_transaction_locked(journal);
		__acquire(&journal->j_state_lock); /* fake out sparse */
		return 1;
	}

	/*
	 * The commit code assumes that it can get enough log space
	 * without forcing a checkpoint.  This is *critical* for
	 * correctness: a checkpoint of a buffer which is also
	 * associated with a committing transaction creates a deadlock,
	 * so commit simply cannot force through checkpoints.
	 *
	 * We must therefore ensure the necessary space in the journal
	 * *before* starting to dirty potentially checkpointed buffers
	 * in the new transaction.
	 * 
	 * 提交代码假设它可以获得足够的日志空间而不强制进行检查点。这对于正确性来说是至关重要的：
	 * 与提交事务相关联的缓冲区的检查点会导致死锁，因此提交不能强制通过检查点。
	 * 
	 * 因此，我们必须在开始在新事务中脏检查点缓冲区之前确保日志中的必要空间。
	 */
	if (jbd2_log_space_left(journal) < journal->j_max_transaction_buffers) {
		atomic_sub(total, &t->t_outstanding_credits);
		read_unlock(&journal->j_state_lock);
		jbd2_might_wait_for_commit(journal);
		write_lock(&journal->j_state_lock);
		if (jbd2_log_space_left(journal) <
					journal->j_max_transaction_buffers)
			__jbd2_log_wait_for_space(journal);
		write_unlock(&journal->j_state_lock);
		__acquire(&journal->j_state_lock); /* fake out sparse */
		return 1;
	}

	/* No reservation? We are done... */
	if (!rsv_blocks)
		return 0;

	needed = atomic_add_return(rsv_blocks, &journal->j_reserved_credits);
	/* We allow at most half of a transaction to be reserved */
	if (needed > journal->j_max_transaction_buffers / 2) {
		sub_reserved_credits(journal, rsv_blocks);
		atomic_sub(total, &t->t_outstanding_credits);
		read_unlock(&journal->j_state_lock);
		jbd2_might_wait_for_commit(journal);
		wait_event(journal->j_wait_reserved,
			 atomic_read(&journal->j_reserved_credits) + rsv_blocks
			 <= journal->j_max_transaction_buffers / 2);
		__acquire(&journal->j_state_lock); /* fake out sparse */
		return 1;
	}
	return 0;
}

/*
 * start_this_handle: Given a handle, deal with any locking or stalling
 * needed to make sure that there is enough journal space for the handle
 * to begin.  Attach the handle to a transaction and set up the
 * transaction's buffer credits.
 * 
 * 给定一个句柄，处理任何锁定或停顿，以确保句柄有足够的日志空间开始。
 * 将句柄附加到事务并设置事务的缓冲区信用。
 */

static int start_this_handle(journal_t *journal, handle_t *handle,
			     gfp_t gfp_mask)
{
	transaction_t	*transaction, *new_transaction = NULL;
	int		blocks = handle->h_total_credits;
	int		rsv_blocks = 0;
	unsigned long ts = jiffies;

	if (handle->h_rsv_handle)
		rsv_blocks = handle->h_rsv_handle->h_total_credits;

	/*
	 * Limit the number of reserved credits to 1/2 of maximum transaction
	 * size and limit the number of total credits to not exceed maximum
	 * transaction size per operation.
	 */
	if ((rsv_blocks > journal->j_max_transaction_buffers / 2) ||
	    (rsv_blocks + blocks > journal->j_max_transaction_buffers)) {
		printk(KERN_ERR "JBD2: %s wants too many credits "
		       "credits:%d rsv_credits:%d max:%d\n",
		       current->comm, blocks, rsv_blocks,
		       journal->j_max_transaction_buffers);
		WARN_ON(1);
		return -ENOSPC;
	}

alloc_transaction:
	/*
	 * This check is racy but it is just an optimization of allocating new
	 * transaction early if there are high chances we'll need it. If we
	 * guess wrong, we'll retry or free unused transaction.
	 */
	if (!data_race(journal->j_running_transaction)) {
		/*
		 * If __GFP_FS is not present, then we may be being called from
		 * inside the fs writeback layer, so we MUST NOT fail.
		 */
		if ((gfp_mask & __GFP_FS) == 0)
			gfp_mask |= __GFP_NOFAIL;
		new_transaction = kmem_cache_zalloc(transaction_cache,
						    gfp_mask);
		if (!new_transaction)
			return -ENOMEM;
	}

	jbd2_debug(3, "New handle %p going live.\n", handle);

	/*
	 * We need to hold j_state_lock until t_updates has been incremented,
	 * for proper journal barrier handling
	 */
repeat:
	read_lock(&journal->j_state_lock);
	BUG_ON(journal->j_flags & JBD2_UNMOUNT);
	if (is_journal_aborted(journal) ||
	    (journal->j_errno != 0 && !(journal->j_flags & JBD2_ACK_ERR))) {
		read_unlock(&journal->j_state_lock);
		jbd2_journal_free_transaction(new_transaction);
		return -EROFS;
	}

	/*
	 * Wait on the journal's transaction barrier if necessary. Specifically
	 * we allow reserved handles to proceed because otherwise commit could
	 * deadlock on page writeback not being able to complete.
	 */
	if (!handle->h_reserved && journal->j_barrier_count) {
		read_unlock(&journal->j_state_lock);
		wait_event(journal->j_wait_transaction_locked,
				journal->j_barrier_count == 0);
		goto repeat;
	}

	if (!journal->j_running_transaction) {
		read_unlock(&journal->j_state_lock);
		if (!new_transaction)
			goto alloc_transaction;
		write_lock(&journal->j_state_lock);
		if (!journal->j_running_transaction &&
		    (handle->h_reserved || !journal->j_barrier_count)) {
			jbd2_get_transaction(journal, new_transaction);
			new_transaction = NULL;
		}
		write_unlock(&journal->j_state_lock);
		goto repeat;
	}

	transaction = journal->j_running_transaction;

	if (!handle->h_reserved) {
		/* We may have dropped j_state_lock - restart in that case */
		if (add_transaction_credits(journal, blocks, rsv_blocks)) {
			/*
			 * add_transaction_credits releases
			 * j_state_lock on a non-zero return
			 */
			__release(&journal->j_state_lock);
			goto repeat;
		}
	} else {
		/*
		 * We have handle reserved so we are allowed to join T_LOCKED
		 * transaction and we don't have to check for transaction size
		 * and journal space. But we still have to wait while running
		 * transaction is being switched to a committing one as it
		 * won't wait for any handles anymore.
		 */
		if (transaction->t_state == T_SWITCH) {
			wait_transaction_switching(journal);
			goto repeat;
		}
		sub_reserved_credits(journal, blocks);
		handle->h_reserved = 0;
	}

	/* OK, account for the buffers that this operation expects to
	 * use and add the handle to the running transaction.
	 */
	update_t_max_wait(transaction, ts);
	handle->h_transaction = transaction;
	handle->h_requested_credits = blocks;
	handle->h_revoke_credits_requested = handle->h_revoke_credits;
	handle->h_start_jiffies = jiffies;
	atomic_inc(&transaction->t_updates);
	atomic_inc(&transaction->t_handle_count);
	jbd2_debug(4, "Handle %p given %d credits (total %d, free %lu)\n",
		  handle, blocks,
		  atomic_read(&transaction->t_outstanding_credits),
		  jbd2_log_space_left(journal));
	read_unlock(&journal->j_state_lock);
	current->journal_info = handle;

	rwsem_acquire_read(&journal->j_trans_commit_map, 0, 0, _THIS_IP_);
	jbd2_journal_free_transaction(new_transaction);
	/*
	 * Ensure that no allocations done while the transaction is open are
	 * going to recurse back to the fs layer.
	 */
	handle->saved_alloc_context = memalloc_nofs_save();
	return 0;
}

/* Allocate a new handle.  This should probably be in a slab... */
static handle_t *new_handle(int nblocks)
{
	handle_t *handle = jbd2_alloc_handle(GFP_NOFS);
	if (!handle)
		return NULL;
	handle->h_total_credits = nblocks;
	handle->h_ref = 1;

	return handle;
}

handle_t *jbd2__journal_start(journal_t *journal, int nblocks, int rsv_blocks,
			      int revoke_records, gfp_t gfp_mask,
			      unsigned int type, unsigned int line_no)
{
	handle_t *handle = journal_current_handle();
	int err;

	if (!journal)
		return ERR_PTR(-EROFS);

	if (handle) {
		J_ASSERT(handle->h_transaction->t_journal == journal);
		handle->h_ref++;
		return handle;
	}

	nblocks += DIV_ROUND_UP(revoke_records,
				journal->j_revoke_records_per_block);
	handle = new_handle(nblocks);	// 确保日志中有nblocks个修改的缓冲区
	if (!handle)
		return ERR_PTR(-ENOMEM);
	if (rsv_blocks) {	// 另外，若rsv_blocks>0，我们也在日志中创建另一个句柄rsv_handle
		handle_t *rsv_handle;

		rsv_handle = new_handle(rsv_blocks);	// 该句柄有rsv_blocks个保留块
		if (!rsv_handle) {
			jbd2_free_handle(handle);
			return ERR_PTR(-ENOMEM);
		}
		rsv_handle->h_reserved = 1;
		rsv_handle->h_journal = journal;
		handle->h_rsv_handle = rsv_handle;
	}
	handle->h_revoke_credits = revoke_records;

	err = start_this_handle(journal, handle, gfp_mask);
	if (err < 0) {
		if (handle->h_rsv_handle)
			jbd2_free_handle(handle->h_rsv_handle);
		jbd2_free_handle(handle);
		return ERR_PTR(err);
	}
	handle->h_type = type;
	handle->h_line_no = line_no;
	trace_jbd2_handle_start(journal->j_fs_dev->bd_dev,
				handle->h_transaction->t_tid, type,
				line_no, nblocks);

	return handle;
}
EXPORT_SYMBOL(jbd2__journal_start);


/**
 * jbd2_journal_start() - Obtain a new handle.
 * @journal: Journal to start transaction on.
 * @nblocks: number of block buffer we might modify
 *
 * We make sure that the transaction can guarantee at least nblocks of
 * modified buffers in the log.  We block until the log can guarantee
 * that much space. Additionally, if rsv_blocks > 0, we also create another
 * handle with rsv_blocks reserved blocks in the journal. This handle is
 * stored in h_rsv_handle. It is not attached to any particular transaction
 * and thus doesn't block transaction commit. If the caller uses this reserved
 * handle, it has to set h_rsv_handle to NULL as otherwise jbd2_journal_stop()
 * on the parent handle will dispose the reserved one. Reserved handle has to
 * be converted to a normal handle using jbd2_journal_start_reserved() before
 * it can be used.
 * 
 * 我们确保事务可以保证日志中至少nblocks个修改的缓冲区。我们阻塞直到日志可以保证这么多的空间。
 * 另外，如果rsv_blocks > 0，我们也在日志中创建另一个句柄，该句柄有rsv_blocks保留块。该句柄
 * 存储在h_rsv_handle中。它不附加到任何特定的事务，因此不会阻塞事务提交。如果调用者使用此保留
 * 句柄，则必须将h_rsv_handle设置为NULL，否则父句柄上的jbd2_journal_stop()将处理保留的句柄。
 * 在保留的句柄可以使用之前，必须使用jbd2_journal_start_reserved()将其转换为正常句柄。
 *
 * Return a pointer to a newly allocated handle, or an ERR_PTR() value
 * on failure.
 */
handle_t *jbd2_journal_start(journal_t *journal, int nblocks)
{
	return jbd2__journal_start(journal, nblocks, 0, 0, GFP_NOFS, 0, 0);
}
EXPORT_SYMBOL(jbd2_journal_start);

static void __jbd2_journal_unreserve_handle(handle_t *handle, transaction_t *t)
{
	journal_t *journal = handle->h_journal;

	WARN_ON(!handle->h_reserved);
	sub_reserved_credits(journal, handle->h_total_credits);
	if (t)
		atomic_sub(handle->h_total_credits, &t->t_outstanding_credits);
}

void jbd2_journal_free_reserved(handle_t *handle)
{
	journal_t *journal = handle->h_journal;

	/* Get j_state_lock to pin running transaction if it exists */
	read_lock(&journal->j_state_lock);
	__jbd2_journal_unreserve_handle(handle, journal->j_running_transaction);
	read_unlock(&journal->j_state_lock);
	jbd2_free_handle(handle);
}
EXPORT_SYMBOL(jbd2_journal_free_reserved);

/**
 * jbd2_journal_start_reserved() - start reserved handle
 * @handle: handle to start
 * @type: for handle statistics
 * @line_no: for handle statistics
 *
 * Start handle that has been previously reserved with jbd2_journal_reserve().
 * This attaches @handle to the running transaction (or creates one if there's
 * not transaction running). Unlike jbd2_journal_start() this function cannot
 * block on journal commit, checkpointing, or similar stuff. It can block on
 * memory allocation or frozen journal though.
 * 
 * 启动先前使用jbd2_journal_reserve()保留的句柄。这将句柄附加到正在运行的事务
 * （如果没有正在运行的事务，则创建一个事务）。与jbd2_journal_start()不同，此函数
 * 不能在日志提交，检查点或类似的东西上阻塞。但是，它可以在内存分配或冻结日志上阻塞。
 *
 * Return 0 on success, non-zero on error - handle is freed in that case.
 */
int jbd2_journal_start_reserved(handle_t *handle, unsigned int type,
				unsigned int line_no)
{
	journal_t *journal = handle->h_journal;
	int ret = -EIO;

	if (WARN_ON(!handle->h_reserved)) {
		/* Someone passed in normal handle? Just stop it. 
		* 有人传进来了普通句柄（非reserved）？停下来 */
		jbd2_journal_stop(handle);
		return ret;
	}
	/*
	 * Usefulness of mixing of reserved and unreserved handles is
	 * questionable. So far nobody seems to need it so just error out.
	 * 
	 * 混合保留和未保留句柄的有用性是可疑的。到目前为止，似乎没有人需要它，所以就出错了。
	 */
	if (WARN_ON(current->journal_info)) {	// 当前进程也不能有普通句柄？
		jbd2_journal_free_reserved(handle);
		return ret;
	}

	handle->h_journal = NULL;
	/*
	 * GFP_NOFS is here because callers are likely from writeback or
	 * similarly constrained call sites
	 */
	ret = start_this_handle(journal, handle, GFP_NOFS);
	if (ret < 0) {
		handle->h_journal = journal;
		jbd2_journal_free_reserved(handle);
		return ret;
	}
	handle->h_type = type;
	handle->h_line_no = line_no;
	trace_jbd2_handle_start(journal->j_fs_dev->bd_dev,
				handle->h_transaction->t_tid, type,
				line_no, handle->h_total_credits);
	return 0;
}
EXPORT_SYMBOL(jbd2_journal_start_reserved);

/**
 * jbd2_journal_extend() - extend buffer credits.
 * @handle:  handle to 'extend'
 * @nblocks: nr blocks to try to extend by.
 * @revoke_records: number of revoke records to try to extend by.
 *
 * Some transactions, such as large extends and truncates, can be done
 * atomically all at once or in several stages.  The operation requests
 * a credit for a number of buffer modifications in advance, but can
 * extend its credit if it needs more.
 *
 * jbd2_journal_extend tries to give the running handle more buffer credits.
 * It does not guarantee that allocation - this is a best-effort only.
 * The calling process MUST be able to deal cleanly with a failure to
 * extend here.
 *
 * Return 0 on success, non-zero on failure.
 *
 * return code < 0 implies an error
 * return code > 0 implies normal transaction-full status.
 * 
 * 一些事务（例如大型扩展和截断）可以一次性或分几个阶段完成。该操作提前为多个缓冲区修改
 * 请求信用，但是如果需要更多，则可以扩展其信用。
 * 
 * jbd2_journal_extend尝试为正在运行的句柄提供更多的缓冲区信用。它不能保证分配-这只是尽力而为。
 * 调用进程必须能够干净地处理此处的扩展失败。
 * 
 * 成功返回0，失败返回非零。
 * 
 * 返回代码<0表示错误
 * 返回代码> 0表示正常的事务完整状态。
 */
int jbd2_journal_extend(handle_t *handle, int nblocks, int revoke_records)
{
	transaction_t *transaction = handle->h_transaction;
	journal_t *journal;
	int result;
	int wanted;

	if (is_handle_aborted(handle))
		return -EROFS;
	journal = transaction->t_journal;

	result = 1;

	read_lock(&journal->j_state_lock);

	/* Don't extend a locked-down transaction! */
	if (transaction->t_state != T_RUNNING) {
		jbd2_debug(3, "denied handle %p %d blocks: "
			  "transaction not running\n", handle, nblocks);
		goto error_out;
	}

	nblocks += DIV_ROUND_UP(
			handle->h_revoke_credits_requested + revoke_records,
			journal->j_revoke_records_per_block) -
		DIV_ROUND_UP(
			handle->h_revoke_credits_requested,
			journal->j_revoke_records_per_block);
	wanted = atomic_add_return(nblocks,
				   &transaction->t_outstanding_credits);

	if (wanted > journal->j_max_transaction_buffers) {
		jbd2_debug(3, "denied handle %p %d blocks: "
			  "transaction too large\n", handle, nblocks);
		atomic_sub(nblocks, &transaction->t_outstanding_credits);
		goto error_out;
	}

	trace_jbd2_handle_extend(journal->j_fs_dev->bd_dev,
				 transaction->t_tid,
				 handle->h_type, handle->h_line_no,
				 handle->h_total_credits,
				 nblocks);

	handle->h_total_credits += nblocks;
	handle->h_requested_credits += nblocks;
	handle->h_revoke_credits += revoke_records;
	handle->h_revoke_credits_requested += revoke_records;
	result = 0;

	jbd2_debug(3, "extended handle %p by %d\n", handle, nblocks);
error_out:
	read_unlock(&journal->j_state_lock);
	return result;
}

static void stop_this_handle(handle_t *handle)
{
	transaction_t *transaction = handle->h_transaction;
	journal_t *journal = transaction->t_journal;
	int revokes;

	J_ASSERT(journal_current_handle() == handle);
	J_ASSERT(atomic_read(&transaction->t_updates) > 0);
	current->journal_info = NULL;
	/*
	 * Subtract necessary revoke descriptor blocks from handle credits. We
	 * take care to account only for revoke descriptor blocks the
	 * transaction will really need as large sequences of transactions with
	 * small numbers of revokes are relatively common.
	 * 
	 * 从句柄信用中减去必要的撤销描述符块。我们小心翼翼地考虑事务真正需要的撤销描述符块，
	 * 因为具有小数量的撤销的大量事务序列相对常见。
	 */
	revokes = handle->h_revoke_credits_requested - handle->h_revoke_credits;
	if (revokes) {
		int t_revokes, revoke_descriptors;
		int rr_per_blk = journal->j_revoke_records_per_block;

		WARN_ON_ONCE(DIV_ROUND_UP(revokes, rr_per_blk)
				> handle->h_total_credits);
		t_revokes = atomic_add_return(revokes,
				&transaction->t_outstanding_revokes);
		revoke_descriptors =
			DIV_ROUND_UP(t_revokes, rr_per_blk) -
			DIV_ROUND_UP(t_revokes - revokes, rr_per_blk);
		handle->h_total_credits -= revoke_descriptors;
	}
	atomic_sub(handle->h_total_credits,
		   &transaction->t_outstanding_credits);
	if (handle->h_rsv_handle)
		__jbd2_journal_unreserve_handle(handle->h_rsv_handle,
						transaction);
	if (atomic_dec_and_test(&transaction->t_updates))
		wake_up(&journal->j_wait_updates);

	rwsem_release(&journal->j_trans_commit_map, _THIS_IP_);
	/*
	 * Scope of the GFP_NOFS context is over here and so we can restore the
	 * original alloc context.
	 * 
	 * GFP_NOFS上下文的范围在这里结束，因此我们可以恢复原始的分配上下文。
	 */
	memalloc_nofs_restore(handle->saved_alloc_context);
}

/**
 * jbd2__journal_restart() - restart a handle .
 * @handle:  handle to restart
 * @nblocks: nr credits requested
 * @revoke_records: number of revoke record credits requested
 * @gfp_mask: memory allocation flags (for start_this_handle)
 *
 * Restart a handle for a multi-transaction filesystem
 * operation.
 *
 * If the jbd2_journal_extend() call above fails to grant new buffer credits
 * to a running handle, a call to jbd2_journal_restart will commit the
 * handle's transaction so far and reattach the handle to a new
 * transaction capable of guaranteeing the requested number of
 * credits. We preserve reserved handle if there's any attached to the
 * passed in handle.
 * 
 * 为多事务文件系统操作重新启动句柄。
 * 
 * 如果上面的jbd2_journal_extend（）调用无法向运行中的句柄授予新的缓冲区信用，
 * 则对jbd2_journal_restart的调用将提交到目前为止的句柄事务，并将句柄重新附加到
 * 能够保证所请求的数量的新事务。如果有任何附加到传入句柄的保留句柄，则我们将其保留。
 */
int jbd2__journal_restart(handle_t *handle, int nblocks, int revoke_records,
			  gfp_t gfp_mask)
{
	transaction_t *transaction = handle->h_transaction;
	journal_t *journal;
	tid_t		tid;
	int		need_to_start;
	int		ret;

	/* If we've had an abort of any type, don't even think about
	 * actually doing the restart! */
	if (is_handle_aborted(handle))
		return 0;
	journal = transaction->t_journal;
	tid = transaction->t_tid;

	/*
	 * First unlink the handle from its current transaction, and start the
	 * commit on that.
	 */
	jbd2_debug(2, "restarting handle %p\n", handle);
	stop_this_handle(handle);
	handle->h_transaction = NULL;

	/*
	 * TODO: If we use READ_ONCE / WRITE_ONCE for j_commit_request we can
 	 * get rid of pointless j_state_lock traffic like this.
	 */
	read_lock(&journal->j_state_lock);
	need_to_start = !tid_geq(journal->j_commit_request, tid);
	read_unlock(&journal->j_state_lock);
	if (need_to_start)
		jbd2_log_start_commit(journal, tid);
	handle->h_total_credits = nblocks +
		DIV_ROUND_UP(revoke_records,
			     journal->j_revoke_records_per_block);
	handle->h_revoke_credits = revoke_records;
	ret = start_this_handle(journal, handle, gfp_mask);
	trace_jbd2_handle_restart(journal->j_fs_dev->bd_dev,
				 ret ? 0 : handle->h_transaction->t_tid,
				 handle->h_type, handle->h_line_no,
				 handle->h_total_credits);
	return ret;
}
EXPORT_SYMBOL(jbd2__journal_restart);


int jbd2_journal_restart(handle_t *handle, int nblocks)
{
	return jbd2__journal_restart(handle, nblocks, 0, GFP_NOFS);
}
EXPORT_SYMBOL(jbd2_journal_restart);

/*
 * Waits for any outstanding t_updates to finish.
 * This is called with write j_state_lock held.
 * 
 * 等待任何未完成的t_updates。 这是在持有write j_state_lock时调用的。
 */
void jbd2_journal_wait_updates(journal_t *journal)
{
	DEFINE_WAIT(wait);

	while (1) {
		/*
		 * Note that the running transaction can get freed under us if
		 * this transaction is getting committed in
		 * jbd2_journal_commit_transaction() ->
		 * jbd2_journal_free_transaction(). This can only happen when we
		 * release j_state_lock -> schedule() -> acquire j_state_lock.
		 * Hence we should everytime retrieve new j_running_transaction
		 * value (after j_state_lock release acquire cycle), else it may
		 * lead to use-after-free of old freed transaction.
		 * 
		 * 注意，如果此事务在jbd2_journal_commit_transaction（）-> 
		 * jbd2_journal_free_transaction（）中提交，则该running transaction可以在此释放。
		 * 这只有在释放j_state_lock-> schedule（）->获取j_state_lock时，才可以发生。
		 * 因此，我们应该每次都检索新的j_running_transaction值（在j_state_lock
		 * 释放-获取 周期之后），否则它可能会导致旧的已释放事务的使用后释放。
		 */
		transaction_t *transaction = journal->j_running_transaction;

		if (!transaction)
			break;

		// &journal->j_wait_updates：等待更新完成的等待队列
		prepare_to_wait(&journal->j_wait_updates, &wait,
				TASK_UNINTERRUPTIBLE);
		if (!atomic_read(&transaction->t_updates)) {
			finish_wait(&journal->j_wait_updates, &wait);
			break;
		}
		write_unlock(&journal->j_state_lock);
		schedule();
		finish_wait(&journal->j_wait_updates, &wait);
		write_lock(&journal->j_state_lock);
	}
}

/**
 * jbd2_journal_lock_updates () - establish a transaction barrier.
 * @journal:  Journal to establish a barrier on.
 *
 * This locks out any further updates from being started, and blocks
 * until all existing updates have completed, returning only once the
 * journal is in a quiescent state with no updates running.
 *
 * The journal lock should not be held on entry.
 * 
 * 创建一个事务屏障
 * 
 * 此函数锁定任何进一步的更新，直到所有现有更新完成为止，仅在日志处于静止状态且没有
 * 正在运行的更新的情况下返回。
 * 
 * 在进入时不应持有日志锁。
 */
void jbd2_journal_lock_updates(journal_t *journal)
{
	jbd2_might_wait_for_commit(journal);

	write_lock(&journal->j_state_lock);
	++journal->j_barrier_count;

	/* Wait until there are no reserved handles */
	if (atomic_read(&journal->j_reserved_credits)) {
		write_unlock(&journal->j_state_lock);
		wait_event(journal->j_wait_reserved,
			   atomic_read(&journal->j_reserved_credits) == 0);
		write_lock(&journal->j_state_lock);
	}

	/* Wait until there are no running t_updates */
	jbd2_journal_wait_updates(journal);

	write_unlock(&journal->j_state_lock);

	/*
	 * We have now established a barrier against other normal updates, but
	 * we also need to barrier against other jbd2_journal_lock_updates() calls
	 * to make sure that we serialise special journal-locked operations
	 * too.
	 * 
	 * 我们现在已经建立了对其他正常更新的屏障，但是我们还需要对其他jbd2_journal_lock_updates（）
	 * 调用进行屏障，以确保我们也对特殊的日志锁定操作进行序列化。
	 */
	mutex_lock(&journal->j_barrier);
}

/**
 * jbd2_journal_unlock_updates () - release barrier
 * @journal:  Journal to release the barrier on.
 *
 * Release a transaction barrier obtained with jbd2_journal_lock_updates().
 *
 * Should be called without the journal lock held.
 */
void jbd2_journal_unlock_updates (journal_t *journal)
{
	J_ASSERT(journal->j_barrier_count != 0);

	mutex_unlock(&journal->j_barrier);
	write_lock(&journal->j_state_lock);
	--journal->j_barrier_count;	// 等待创建屏障锁的进程数
	write_unlock(&journal->j_state_lock);
	wake_up_all(&journal->j_wait_transaction_locked);
}

static void warn_dirty_buffer(struct buffer_head *bh)
{
	printk(KERN_WARNING
	       "JBD2: Spotted dirty metadata buffer (dev = %pg, blocknr = %llu). "
	       "There's a risk of filesystem corruption in case of system "
	       "crash.\n",
	       bh->b_bdev, (unsigned long long)bh->b_blocknr);
}

/* Call t_frozen trigger and copy buffer data into jh->b_frozen_data. 
 * 调用t_frozen触发器并将缓冲区数据复制到jh->b_frozen_data中 */
static void jbd2_freeze_jh_data(struct journal_head *jh)
{
	struct page *page;
	int offset;
	char *source;
	struct buffer_head *bh = jh2bh(jh);

	J_EXPECT_JH(jh, buffer_uptodate(bh), "Possible IO failure.\n");
	page = bh->b_page;
	offset = offset_in_page(bh->b_data);
	source = kmap_atomic(page);
	/* Fire data frozen trigger just before we copy the data */
	jbd2_buffer_frozen_trigger(jh, source + offset, jh->b_triggers);
	memcpy(jh->b_frozen_data, source + offset, bh->b_size);
	kunmap_atomic(source);

	/*
	 * Now that the frozen data is saved off, we need to store any matching
	 * triggers.
	 */
	jh->b_frozen_triggers = jh->b_triggers;
}

/*
 * If the buffer is already part of the current transaction, then there
 * is nothing we need to do.  If it is already part of a prior
 * transaction which we are still committing to disk, then we need to
 * make sure that we do not overwrite the old copy: we do copy-out to
 * preserve the copy going to disk.  We also account the buffer against
 * the handle's metadata buffer credits (unless the buffer is already
 * part of the transaction, that is).
 * 
 * 如果缓冲区已经是当前事务的一部分，则我们无需执行任何操作。如果它已经是我们仍在提交到磁盘
 * 的先前事务的一部分，则我们需要确保我们不会覆盖旧副本：我们执行复制以保留副本到磁盘。我们还
 * 根据句柄的元数据缓冲区信用额度计算缓冲区（除非缓冲区已经是事务的一部分）。
 */
static int
do_get_write_access(handle_t *handle, struct journal_head *jh,
			int force_copy)
{
	struct buffer_head *bh;
	// handle->h_transaction：此更新是哪个复合事务的一部分
	transaction_t *transaction = handle->h_transaction;
	journal_t *journal;
	int error;
	char *frozen_buffer = NULL;
	unsigned long start_lock, time_lock;

	journal = transaction->t_journal;	// t_journal：指向该事物journal的指针

	jbd2_debug(5, "journal_head %p, force_copy %d\n", jh, force_copy);

	JBUFFER_TRACE(jh, "entry");
repeat:
	bh = jh2bh(jh);

	/* @@@ Need to check for errors here at some point. */

 	start_lock = jiffies;
	lock_buffer(bh);
	spin_lock(&jh->b_state_lock);

	/* If it takes too long to lock the buffer, trace it */
	time_lock = jbd2_time_diff(start_lock, jiffies);
	if (time_lock > HZ/10)
		trace_jbd2_lock_buffer_stall(bh->b_bdev->bd_dev,
			jiffies_to_msecs(time_lock));

	/* We now hold the buffer lock so it is safe to query the buffer
	 * state.  Is the buffer dirty?
	 *
	 * If so, there are two possibilities.  The buffer may be
	 * non-journaled, and undergoing a quite legitimate writeback.
	 * Otherwise, it is journaled, and we don't expect dirty buffers
	 * in that state (the buffers should be marked JBD_Dirty
	 * instead.)  So either the IO is being done under our own
	 * control and this is a bug, or it's a third party IO such as
	 * dump(8) (which may leave the buffer scheduled for read ---
	 * ie. locked but not dirty) or tune2fs (which may actually have
	 * the buffer dirtied, ugh.)  
	 * 
	 * 我们现在持有缓冲区锁，因此可以安全地查询缓冲区状态。缓冲区是否脏了？
	 * 
	 * 如果是脏了，那么有两种可能性。缓冲区可能是非日志化的，并且正在进行非常合法的回写。
	 * 否则，它是日志化的，我们不希望在该状态下出现脏缓冲区（缓冲区应标记为JBD_Dirty）。
	 * 因此，要么IO在我们自己的控制下进行，这是一个bug；要么这是第三方IO，例如dump（8）
	 * （可能会使缓冲区计划读取 - 即锁定但不脏），或者tune2fs（可能实际上已经脏了缓冲区，呃）。
	 * */

	if (buffer_dirty(bh) && jh->b_transaction) {
		warn_dirty_buffer(bh);	// 警告脏缓冲区：缓冲区在事务中，不应该为脏，这里是一个bug
		/*
		 * We need to clean the dirty flag and we must do it under the
		 * buffer lock to be sure we don't race with running write-out.
		 * 
		 * 我们需要清除脏标志，我们必须在缓冲区锁下执行，以确保我们不会与正在运行的写出竞争。
		 */
		JBUFFER_TRACE(jh, "Journalling dirty buffer");
		clear_buffer_dirty(bh);
		/*
		 * The buffer is going to be added to BJ_Reserved list now and
		 * nothing guarantees jbd2_journal_dirty_metadata() will be
		 * ever called for it. So we need to set jbddirty bit here to
		 * make sure the buffer is dirtied and written out when the
		 * journaling machinery is done with it.
		 * 
		 * 缓冲区现在将被添加到BJ_Reserved列表中，没有任何保证jbd2_journal_dirty_metadata()
		 * 将被调用。因此，我们需要在这里设置jbddirty位，以确保在journaling机制完成后，
		 * 缓冲区被脏化并写出。
		 */
		set_buffer_jbddirty(bh);
	}

	error = -EROFS;
	if (is_handle_aborted(handle)) {
		spin_unlock(&jh->b_state_lock);
		unlock_buffer(bh);
		goto out;
	}
	error = 0;

	/*
	 * The buffer is already part of this transaction if b_transaction or
	 * b_next_transaction points to it
	 * 
	 * 如果b_transaction或b_next_transaction指向它，则缓冲区已经是该事务的一部分
	 */
	if (jh->b_transaction == transaction ||
	    jh->b_next_transaction == transaction) {
		unlock_buffer(bh);
		goto done;
	}

	/*
	 * this is the first time this transaction is touching this buffer,
	 * reset the modified flag
	 * 
	 * （buffer之前不在transaction中，初次出现在transaction里面）
	 * 这是该事务第一次接触该缓冲区，重置修改标志（modified flag）
	 */
	jh->b_modified = 0;

	/*
	 * If the buffer is not journaled right now, we need to make sure it
	 * doesn't get written to disk before the caller actually commits the
	 * new data
	 * 
	 * 如果缓冲区现在没有被放进journal（not journaled），我们需要确保在调用者实际提交
	 * 新数据之前，buffer不会被写入磁盘
	 * << 这就是日志提供写原子性的来源 >>
	 */
	if (!jh->b_transaction) {
		JBUFFER_TRACE(jh, "no transaction");
		J_ASSERT_JH(jh, !jh->b_next_transaction);
		JBUFFER_TRACE(jh, "file as BJ_Reserved");
		/*
		 * Make sure all stores to jh (b_modified, b_frozen_data) are
		 * visible before attaching it to the running transaction.
		 * Paired with barrier in jbd2_write_access_granted()
		 * 
		 * 在将其附加到running transaction之前，确保jh的所有存储（b_modified，b_frozen_data）
		 * 是可见的。与jbd2_write_access_granted()中的barrier配对。
		 */
		smp_wmb();
		spin_lock(&journal->j_list_lock);
		if (test_clear_buffer_dirty(bh)) {
			/*
			 * Execute buffer dirty clearing and jh->b_transaction
			 * assignment under journal->j_list_lock locked to
			 * prevent bh being removed from checkpoint list if
			 * the buffer is in an intermediate state (not dirty
			 * and jh->b_transaction is NULL).
			 * 
			 * 在journal->j_list_lock锁定的情况下执行缓冲区脏清除和jh->b_transaction
			 * 赋值，以防止bh从检查点列表中删除，如果缓冲区处于中间状态（不脏和
			 * jh->b_transaction为NULL）。
			 */
			JBUFFER_TRACE(jh, "Journalling dirty buffer");
			set_buffer_jbddirty(bh);
		}
		__jbd2_journal_file_buffer(jh, transaction, BJ_Reserved);
		spin_unlock(&journal->j_list_lock);
		unlock_buffer(bh);
		goto done;
	}
	unlock_buffer(bh);

	/*
	 * If there is already a copy-out version of this buffer, then we don't
	 * need to make another one
	 * 
	 * 如果已经有该缓冲区的copy-out版本，则我们不需要再做一个
	 */
	if (jh->b_frozen_data) {
		JBUFFER_TRACE(jh, "has frozen data");
		J_ASSERT_JH(jh, jh->b_next_transaction == NULL);
		goto attach_next;
	}

	JBUFFER_TRACE(jh, "owned by older transaction");
	J_ASSERT_JH(jh, jh->b_next_transaction == NULL);
	J_ASSERT_JH(jh, jh->b_transaction == journal->j_committing_transaction);

	/*
	 * There is one case we have to be very careful about.  If the
	 * committing transaction is currently writing this buffer out to disk
	 * and has NOT made a copy-out, then we cannot modify the buffer
	 * contents at all right now.  The essence of copy-out is that it is
	 * the extra copy, not the primary copy, which gets journaled.  If the
	 * primary copy is already going to disk then we cannot do copy-out
	 * here.
	 * 
	 * 有一种情况我们必须非常小心。如果提交事务当前正在将该缓冲区写入磁盘，并且没有做copy-out，
	 * 那么我们现在不能修改缓冲区内容。copy-out的本质是，被journal的是额外的副本，而不是主副本。
	 * 如果主要副本已经要写入磁盘，那么我们不能在这里做copy-out。
	 * 注：Z-Journal论文中的已发送写请求？
	 */
	if (buffer_shadow(bh)) {
		JBUFFER_TRACE(jh, "on shadow: sleep");
		spin_unlock(&jh->b_state_lock);
		wait_on_bit_io(&bh->b_state, BH_Shadow, TASK_UNINTERRUPTIBLE);
		goto repeat;
	}

	/*
	 * Only do the copy if the currently-owning transaction still needs it.
	 * If buffer isn't on BJ_Metadata list, the committing transaction is
	 * past that stage (here we use the fact that BH_Shadow is set under
	 * bh_state lock together with refiling to BJ_Shadow list and at this
	 * point we know the buffer doesn't have BH_Shadow set).
	 *
	 * Subtle point, though: if this is a get_undo_access, then we will be
	 * relying on the frozen_data to contain the new value of the
	 * committed_data record after the transaction, so we HAVE to force the
	 * frozen_data copy in that case.
	 * 
	 * 只有在当前拥有的事务仍然需要它时才进行复制。如果缓冲区不在BJ_Metadata列表上，
	 * 则提交事务已经过了这个阶段（这里我们使用BH_Shadow在bh_state锁下设置的事实，
	 * 以及重新填充到BJ_Shadow列表中，并且在这一点上，我们知道缓冲区没有BH_Shadow设置）。
	 * 
	 * 但是，如果这是一个get_undo_access，则我们将依赖于frozen_data在事务之后包含committed_data
	 * 记录的新值，因此在这种情况下我们必须强制frozen_data复制。
	 */
	if (jh->b_jlist == BJ_Metadata || force_copy) {
		JBUFFER_TRACE(jh, "generate frozen data");
		if (!frozen_buffer) {
			JBUFFER_TRACE(jh, "allocate memory for buffer");
			spin_unlock(&jh->b_state_lock);
			frozen_buffer = jbd2_alloc(jh2bh(jh)->b_size,
						   GFP_NOFS | __GFP_NOFAIL);
			goto repeat;
		}
		jh->b_frozen_data = frozen_buffer;
		frozen_buffer = NULL;
		jbd2_freeze_jh_data(jh);
	}
attach_next:
	/*
	 * Make sure all stores to jh (b_modified, b_frozen_data) are visible
	 * before attaching it to the running transaction. Paired with barrier
	 * in jbd2_write_access_granted()
	 * 
	 * 确保将所有存储到jh（b_modified，b_frozen_data）在将其附加到运行事务之前可见。
	 * 注：可见指通过内存屏障保证了数据对所有线程的可见性？
	 */
	smp_wmb();
	jh->b_next_transaction = transaction;

done:
	spin_unlock(&jh->b_state_lock);

	/*
	 * If we are about to journal a buffer, then any revoke pending on it is
	 * no longer valid
	 * 
	 * 如果我们要记录一个缓冲区，那么任何挂起的撤销都不再有效
	 */
	jbd2_journal_cancel_revoke(handle, jh);

out:
	if (unlikely(frozen_buffer))	/* It's usually NULL */
		jbd2_free(frozen_buffer, bh->b_size);

	JBUFFER_TRACE(jh, "exit");
	return error;
}

/* Fast check whether buffer is already attached to the required transaction *
 * 快速检查缓冲区是否已附加到所需的事务 */
static bool jbd2_write_access_granted(handle_t *handle, struct buffer_head *bh,
							bool undo)
{
	struct journal_head *jh;
	bool ret = false;

	/* Dirty buffers require special handling... */
	if (buffer_dirty(bh))
		return false;

	/*
	 * RCU protects us from dereferencing freed pages. So the checks we do
	 * are guaranteed not to oops. However the jh slab object can get freed
	 * & reallocated while we work with it. So we have to be careful. When
	 * we see jh attached to the running transaction, we know it must stay
	 * so until the transaction is committed. Thus jh won't be freed and
	 * will be attached to the same bh while we run.  However it can
	 * happen jh gets freed, reallocated, and attached to the transaction
	 * just after we get pointer to it from bh. So we have to be careful
	 * and recheck jh still belongs to our bh before we return success.
	 * 
	 * RCU保护我们免受取消引用释放的页面。因此，我们所做的检查保证不会出现问题。
	 * 但是，当我们使用它时，jh slab对象可以被释放并重新分配。所以我们必须小心。
	 * 当我们看到jh附加到正在运行的事务时，我们知道它必须保持这样，直到事务提交。
	 * 因此，jh不会被释放，并且在我们运行时将附加到相同的bh。但是，当我们从bh获取指向jh的指针后，
	 * jh可能会被释放，重新分配，并附加到事务中。因此，我们必须小心，并在返回成功之前
	 * 重新检查jh是否仍然属于我们的bh。
	 */
	rcu_read_lock();
	if (!buffer_jbd(bh))
		goto out;
	/* This should be bh2jh() but that doesn't work with inline functions */
	jh = READ_ONCE(bh->b_private);
	if (!jh)
		goto out;
	/* For undo access buffer must have data copied */
	if (undo && !jh->b_committed_data)
		goto out;
	if (READ_ONCE(jh->b_transaction) != handle->h_transaction &&
	    READ_ONCE(jh->b_next_transaction) != handle->h_transaction)
		goto out;
	/*
	 * There are two reasons for the barrier here:
	 * 1) Make sure to fetch b_bh after we did previous checks so that we
	 * detect when jh went through free, realloc, attach to transaction
	 * while we were checking. Paired with implicit barrier in that path.
	 * 2) So that access to bh done after jbd2_write_access_granted()
	 * doesn't get reordered and see inconsistent state of concurrent
	 * do_get_write_access().
	 */
	smp_mb();
	if (unlikely(jh->b_bh != bh))
		goto out;
	ret = true;
out:
	rcu_read_unlock();
	return ret;
}

/**
 * jbd2_journal_get_write_access() - notify intent to modify a buffer
 *				     for metadata (not data) update.
 * @handle: transaction to add buffer modifications to
 * @bh:     bh to be used for metadata writes
 *
 * Returns: error code or 0 on success.
 *
 * In full data journalling mode the buffer may be of type BJ_AsyncData,
 * because we're ``write()ing`` a buffer which is also part of a shared mapping.
 * 
 * 为元数据（而不是数据）更新通知修改缓冲区的意图。
 * 在 full data journalling 模式下，缓冲区可能是BJ_AsyncData类型，因为我们正在“写入”也是共享映射的一部分的缓冲区。
 */

int jbd2_journal_get_write_access(handle_t *handle, struct buffer_head *bh)
{
	struct journal_head *jh;
	int rc;

	if (is_handle_aborted(handle))
		return -EROFS;

	if (jbd2_write_access_granted(handle, bh, false))
		return 0;

	jh = jbd2_journal_add_journal_head(bh);
	/* We do not want to get caught playing with fields which the
	 * log thread also manipulates.  Make sure that the buffer
	 * completes any outstanding IO before proceeding. */
	rc = do_get_write_access(handle, jh, 0);
	jbd2_journal_put_journal_head(jh);
	return rc;
}


/*
 * When the user wants to journal a newly created buffer_head
 * (ie. getblk() returned a new buffer and we are going to populate it
 * manually rather than reading off disk), then we need to keep the
 * buffer_head locked until it has been completely filled with new
 * data.  In this case, we should be able to make the assertion that
 * the bh is not already part of an existing transaction.
 *
 * The buffer should already be locked by the caller by this point.
 * There is no lock ranking violation: it was a newly created,
 * unlocked buffer beforehand. 
 * 
 * 当用户想要 journal 新创建的buffer_head时（即getblk（）返回一个新的缓冲区，
 * 我们将手动填充它而不是从磁盘读取），那么我们需要保持缓冲区头锁定，
 * 直到它已经完全填充了新数据。在这种情况下，我们应该能够断言bh不是已经存在的事务的一部分。
 * 
 * 在这一点上，缓冲区应该已经被调用者锁定。没有锁定排名违规：之前是一个新创建的，未锁定的缓冲区头。
 * */

/**
 * jbd2_journal_get_create_access () - notify intent to use newly created bh
 * @handle: transaction to new buffer to
 * @bh: new buffer.
 *
 * Call this if you create a new bh.
 * 
 * 通知意图使用新创建的bh
 * 如果你创建一个新的bh，请调用此函数。
 */
int jbd2_journal_get_create_access(handle_t *handle, struct buffer_head *bh)
{
	transaction_t *transaction = handle->h_transaction;
	journal_t *journal;
	struct journal_head *jh = jbd2_journal_add_journal_head(bh);
	int err;

	jbd2_debug(5, "journal_head %p\n", jh);
	err = -EROFS;
	if (is_handle_aborted(handle))
		goto out;
	journal = transaction->t_journal;
	err = 0;

	JBUFFER_TRACE(jh, "entry");
	/*
	 * The buffer may already belong to this transaction due to pre-zeroing
	 * in the filesystem's new_block code.  It may also be on the previous,
	 * committing transaction's lists, but it HAS to be in Forget state in
	 * that case: the transaction must have deleted the buffer for it to be
	 * reused here.
	 * 
	 * 由于文件系统的 new_block 代码中的预清零，缓冲区可能已经属于此事务。
	 * 它也可能在上一个 committing 事务的列表中，但是在这种情况下，它必须处于Forget状态：
	 * 事务必须删除缓冲区才能在此处重用它。
	 */
	spin_lock(&jh->b_state_lock);
	J_ASSERT_JH(jh, (jh->b_transaction == transaction ||
		jh->b_transaction == NULL ||
		(jh->b_transaction == journal->j_committing_transaction &&
			  jh->b_jlist == BJ_Forget)));

	J_ASSERT_JH(jh, jh->b_next_transaction == NULL);
	J_ASSERT_JH(jh, buffer_locked(jh2bh(jh)));

	// 拥有此缓冲区元数据的复合事务指针为空
	if (jh->b_transaction == NULL) {
		/*
		 * Previous jbd2_journal_forget() could have left the buffer
		 * with jbddirty bit set because it was being committed. When
		 * the commit finished, we've filed the buffer for
		 * checkpointing and marked it dirty. Now we are reallocating
		 * the buffer so the transaction freeing it must have
		 * committed and so it's safe to clear the dirty bit.
		 * 
		 * 以前的 jbd2_journal_forget() 可能会使缓冲区的 jbddirty 位设置，
		 * 因为它正在被提交。 当提交完成时，我们已经为检查点归档了缓冲区并将其标记为脏。
		 * 现在我们正在重新分配缓冲区，因此释放它的事务必须已经提交，因此可以安全地清除脏位。
		 */
		clear_buffer_dirty(jh2bh(jh));
		/* first access by this transaction */
		jh->b_modified = 0;

		JBUFFER_TRACE(jh, "file as BJ_Reserved");
		spin_lock(&journal->j_list_lock);
		// 在给定的事务列表类型上归档一个缓冲区
		__jbd2_journal_file_buffer(jh, transaction, BJ_Reserved);
		spin_unlock(&journal->j_list_lock);
	} else if (jh->b_transaction == journal->j_committing_transaction) {
		// <拥有此缓冲区元数据的复合事务>的指针指向<journal中的committing事务>
		// 新事务touch该jh的时候，发现已经有事务（该journal下的committing事务）在提交它：
		/* first access by this transaction */
		jh->b_modified = 0;

		JBUFFER_TRACE(jh, "set next transaction");
		spin_lock(&journal->j_list_lock);
		// 将该jh的b_next_transaction指针指向正在修改缓冲区元数据的复合事务
		jh->b_next_transaction = transaction;
		// TODO: 重要，这个transaction一定是journal->j_running_transaction吗？
		spin_unlock(&journal->j_list_lock);
	}
	spin_unlock(&jh->b_state_lock);

	/*
	 * akpm: I added this.  ext3_alloc_branch can pick up new indirect
	 * blocks which contain freed but then revoked metadata.  We need
	 * to cancel the revoke in case we end up freeing it yet again
	 * and the reallocating as data - this would cause a second revoke,
	 * which hits an assertion error.
	 * 
	 * akpm：我添加了这个。 ext3_alloc_branch 可以挑选出包含已释放但已撤销的元数据的新间接块。
	 * 我们需要取消撤销，以防我们最终再次释放它，然后重新分配为数据 - 这将导致第二次撤销，这会导致断言错误。
	 * TODO: 这是在说啥，重要吗？
	 */
	JBUFFER_TRACE(jh, "cancelling revoke");
	jbd2_journal_cancel_revoke(handle, jh);
out:
	jbd2_journal_put_journal_head(jh);
	return err;
}

/**
 * jbd2_journal_get_undo_access() -  Notify intent to modify metadata with
 *     non-rewindable consequences
 * @handle: transaction
 * @bh: buffer to undo
 * 
 * 通知意图进行具有不可回退后果的元数据修改
 *
 * Sometimes there is a need to distinguish between metadata which has
 * been committed to disk and that which has not.  The ext3fs code uses
 * this for freeing and allocating space, we have to make sure that we
 * do not reuse freed space until the deallocation has been committed,
 * since if we overwrote that space we would make the delete
 * un-rewindable in case of a crash.
 *
 * To deal with that, jbd2_journal_get_undo_access requests write access to a
 * buffer for parts of non-rewindable operations such as delete
 * operations on the bitmaps.  The journaling code must keep a copy of
 * the buffer's contents prior to the undo_access call until such time
 * as we know that the buffer has definitely been committed to disk.
 *
 * We never need to know which transaction the committed data is part
 * of, buffers touched here are guaranteed to be dirtied later and so
 * will be committed to a new transaction in due course, at which point
 * we can discard the old committed data pointer.
 * 
 * 有时需要区分已提交到磁盘的元数据和未提交到磁盘的元数据。 ext3fs 代码用于释放和分配空间，
 * 我们必须确保在 *取消分配操作* 被提交之前不会重用已释放的空间，因为如果我们覆盖该空间，
 * 则在崩溃的情况下将使删除不可回滚。
 * 
 * 为了解决这个问题，jbd2_journal_get_undo_access 请求对缓冲区的写访问权限，
 * 用于非可回退操作的部分，例如位图上的删除操作。 journaling 代码必须在 undo_access 调用之前
 * 保留缓冲区内容的副本，直到我们知道缓冲区已明确提交到磁盘为止。
 * 
 * 我们永远不需要知道已提交数据是哪个事务的一部分，这里触及的缓冲区保证稍后会被标记为脏，
 * 因此将在适当的时候提交到新事务中，此时我们可以丢弃旧的已提交数据指针。
 *
 * Returns error number or 0 on success.
 */
int jbd2_journal_get_undo_access(handle_t *handle, struct buffer_head *bh)
{
	int err;
	struct journal_head *jh;
	char *committed_data = NULL;

	if (is_handle_aborted(handle))
		return -EROFS;

	if (jbd2_write_access_granted(handle, bh, true))
		return 0;

	jh = jbd2_journal_add_journal_head(bh);
	JBUFFER_TRACE(jh, "entry");

	/*
	 * Do this first --- it can drop the journal lock, so we want to
	 * make sure that obtaining the committed_data is done
	 * atomically wrt. completion of any outstanding commits.
	 * 
	 * 首先执行此操作 - 它可以释放日志锁，因此我们希望确保在完成任何未完成的提交时，
	 * 以原子方式获得committed_data。
	 */
	err = do_get_write_access(handle, jh, 1);
	if (err)
		goto out;

repeat:
	if (!jh->b_committed_data)
		committed_data = jbd2_alloc(jh2bh(jh)->b_size,
					    GFP_NOFS|__GFP_NOFAIL);

	spin_lock(&jh->b_state_lock);
	// 下面的if：缓冲区保存的副本为空，那就拷过来
	if (!jh->b_committed_data) {
		/* Copy out the current buffer contents into the
		 * preserved, committed copy. 
		 * 
		 * 将当前缓冲区内容复制到保留的已提交副本(jh->b_committed_data)中。
		 */
		JBUFFER_TRACE(jh, "generate b_committed data");
		if (!committed_data) {	// committed_data没有被分配出内存，重新来过
			spin_unlock(&jh->b_state_lock);
			goto repeat;
		}
		// 到这里committed_data已经被分配了内存，将地址赋给jh->b_committed_data
		// 并且将committed_data置空，这样就只有jh->b_committed_data能操作这段内存
		// 最后将buffer_head的内容拷贝到jh->b_committed_data中
		jh->b_committed_data = committed_data;
		committed_data = NULL;
		memcpy(jh->b_committed_data, bh->b_data, bh->b_size);
	}
	spin_unlock(&jh->b_state_lock);
out:
	jbd2_journal_put_journal_head(jh);
	if (unlikely(committed_data))
		jbd2_free(committed_data, bh->b_size);
	return err;
}

/**
 * jbd2_journal_set_triggers() - Add triggers for commit writeout
 * @bh: buffer to trigger on
 * @type: struct jbd2_buffer_trigger_type containing the trigger(s).
 *
 * Set any triggers on this journal_head.  This is always safe, because
 * triggers for a committing buffer will be saved off, and triggers for
 * a running transaction will match the buffer in that transaction.
 *
 * Call with NULL to clear the triggers.
 * 
 * 添加提交写出(commit writeout)的触发器
 * @bh: 要触发的缓冲区
 * @type: 包含触发器的 struct jbd2_buffer_trigger_type
 * 
 * 设置此 journal_head 上的任何触发器。这总是安全的，因为 committing buffer 的触发器将被保存，
 * 并且 running transaction 的触发器将与该事务中的缓冲区匹配。
 */
void jbd2_journal_set_triggers(struct buffer_head *bh,
			       struct jbd2_buffer_trigger_type *type)
{
	// jh到bh比较简单，直接jh2bh(jh)；而bh->jh比较复杂
	struct journal_head *jh = jbd2_journal_grab_journal_head(bh);

	if (WARN_ON_ONCE(!jh))
		return;
	jh->b_triggers = type;
	jbd2_journal_put_journal_head(jh);
}

void jbd2_buffer_frozen_trigger(struct journal_head *jh, void *mapped_data,
				struct jbd2_buffer_trigger_type *triggers)
{
	struct buffer_head *bh = jh2bh(jh);

	if (!triggers || !triggers->t_frozen)
		return;

	triggers->t_frozen(triggers, bh, mapped_data, bh->b_size);
}

void jbd2_buffer_abort_trigger(struct journal_head *jh,
			       struct jbd2_buffer_trigger_type *triggers)
{
	if (!triggers || !triggers->t_abort)
		return;

	triggers->t_abort(triggers, jh2bh(jh));
}

/**
 * jbd2_journal_dirty_metadata() -  mark a buffer as containing dirty metadata
 * @handle: transaction to add buffer to.
 * @bh: buffer to mark
 *
 * mark dirty metadata which needs to be journaled as part of the current
 * transaction.
 *
 * The buffer must have previously had jbd2_journal_get_write_access()
 * called so that it has a valid journal_head attached to the buffer
 * head.
 *
 * The buffer is placed on the transaction's metadata list and is marked
 * as belonging to the transaction.
 *
 * Returns error number or 0 on success.
 * 
 * 将缓冲区标记为包含脏元数据（包含了将缓冲区添加到当前事务中）
 * @handle: 要添加缓冲区的事务
 * @bh: 要标记的缓冲区
 * 
 * 标记需要作为当前事务的一部分被 journal 的脏元数据。
 * 缓冲区必须先前调用 jbd2_journal_get_write_access()，以便它具有附加到 buffer head 
 * 的有效 journal_head。缓冲区被放置在事务的元数据列表上，并标记为属于事务。
 * 
 * 返回错误号或成功的0。
 * 
 * 
 * Special care needs to be taken if the buffer already belongs to the
 * current committing transaction (in which case we should have frozen
 * data present for that commit).  In that case, we don't relink the
 * buffer: that only gets done when the old transaction finally
 * completes its commit.
 * 
 * 如果缓冲区已经属于当前提交事务(在这种情况下，我们应该为该提交冻结数据)，
 * 那么需要特别小心。在这种情况下，我们不会重新链接缓冲区：只有当旧事务最终完成其提交时，
 * 才会执行此操作。
 */
int jbd2_journal_dirty_metadata(handle_t *handle, struct buffer_head *bh)
{
	transaction_t *transaction = handle->h_transaction;
	journal_t *journal;
	struct journal_head *jh;
	int ret = 0;

	if (!buffer_jbd(bh))
		return -EUCLEAN;

	/*
	 * We don't grab jh reference here since the buffer must be part
	 * of the running transaction.
	 * 
	 * 我们不在这里抓取 jh 引用，因为缓冲区必须是运行事务的一部分。
	 */
	jh = bh2jh(bh);
	jbd2_debug(5, "journal_head %p\n", jh);
	JBUFFER_TRACE(jh, "entry");

	/*
	 * This and the following assertions are unreliable since we may see jh
	 * in inconsistent state unless we grab bh_state lock. But this is
	 * crucial to catch bugs so let's do a reliable check until the
	 * lockless handling is fully proven.
	 * 
	 * 这个和下面的断言是不可靠的，因为我们可能会看到 jh 处于不一致的状态，
	 * 除非我们抓住 bh_state 锁。但这对于捕获错误至关重要，因此让我们进行可靠的检查，
	 * 直到无锁句柄被完全证明。
	 */
	if (data_race(jh->b_transaction != transaction &&
	    jh->b_next_transaction != transaction)) {
		spin_lock(&jh->b_state_lock);
		J_ASSERT_JH(jh, jh->b_transaction == transaction ||
				jh->b_next_transaction == transaction);
		spin_unlock(&jh->b_state_lock);
	}
	// 下面这个if：如果jh->modified == 1，
	// 那就表明buffer已在当前事务中，所以此时jh数据类型必须是BJ_Metadata，不然就报错
	if (jh->b_modified == 1) {
		/* If it's in our transaction it must be in BJ_Metadata list. */
		if (data_race(jh->b_transaction == transaction &&
		    jh->b_jlist != BJ_Metadata)) {
			spin_lock(&jh->b_state_lock);
			if (jh->b_transaction == transaction &&
			    jh->b_jlist != BJ_Metadata)
				pr_err("JBD2: assertion failure: h_type=%u "
				       "h_line_no=%u block_no=%llu jlist=%u\n",
				       handle->h_type, handle->h_line_no,
				       (unsigned long long) bh->b_blocknr,
				       jh->b_jlist);
			J_ASSERT_JH(jh, jh->b_transaction != transaction ||
					jh->b_jlist == BJ_Metadata);
			spin_unlock(&jh->b_state_lock);
		}
		goto out;
	}

	journal = transaction->t_journal;
	spin_lock(&jh->b_state_lock);

	if (is_handle_aborted(handle)) {
		/*
		 * Check journal aborting with @jh->b_state_lock locked,
		 * since 'jh->b_transaction' could be replaced with
		 * 'jh->b_next_transaction' during old transaction
		 * committing if journal aborted, which may fail
		 * assertion on 'jh->b_frozen_data == NULL'.
		 * 
		 * 在 @jh->b_state_lock 锁定的情况下检查日志中止，因为如果日志中止，
		 * 'jh->b_transaction' 可能会在旧事务提交期间被 'jh->b_next_transaction' 替换，
		 * 这可能会在 'jh->b_frozen_data == NULL' 上失败断言。
		 * TODO: 在jh->b_frozen_data == NULL上失败断言在代码哪个位置？
		 */
		ret = -EROFS;
		goto out_unlock_bh;
	}

	// 这个if：如果jh->b_modified == 0，
	// 那应该把buffer放到当前事务的BJ_Metadata链表中，并且把jh->b_modified置为1
	// TODO: 此时buffer在BJ_Metadata链表中吗？
	// 先修改jh->b_modified为1
	if (jh->b_modified == 0) {
		/*
		 * This buffer's got modified and becoming part
		 * of the transaction. This needs to be done
		 * once a transaction -bzzz
		 */
		if (WARN_ON_ONCE(jbd2_handle_buffer_credits(handle) <= 0)) {
			ret = -ENOSPC;
			goto out_unlock_bh;
		}
		jh->b_modified = 1;
		handle->h_total_credits--;	// 从这里看来，每个buffer都会消耗一个credit
	}

	/*
	 * fastpath, to avoid expensive locking.  If this buffer is already
	 * on the running transaction's metadata list there is nothing to do.
	 * Nobody can take it off again because there is a handle open.
	 * I _think_ we're OK here with SMP barriers - a mistaken decision will
	 * result in this test being false, so we go in and take the locks.
	 * 
	 * 快速路径，以避免昂贵的锁定。如果此缓冲区已在 running transaction 的元数据列表上，
	 * 则无需执行任何操作。没有人可以再次将其取出，因为有一个句柄打开。
	 * 我认为我们在这里使用 SMP 屏障是可以的 - 错误的决定将导致此测试为 false，
	 * 因此我们进入并获取锁。
	 */
	if (jh->b_transaction == transaction && jh->b_jlist == BJ_Metadata) {
		JBUFFER_TRACE(jh, "fastpath");
		if (unlikely(jh->b_transaction !=
			     journal->j_running_transaction)) {
			printk(KERN_ERR "JBD2: %s: "
			       "jh->b_transaction (%llu, %p, %u) != "
			       "journal->j_running_transaction (%p, %u)\n",
			       journal->j_devname,
			       (unsigned long long) bh->b_blocknr,
			       jh->b_transaction,
			       jh->b_transaction ? jh->b_transaction->t_tid : 0,
			       journal->j_running_transaction,
			       journal->j_running_transaction ?
			       journal->j_running_transaction->t_tid : 0);
			ret = -EINVAL;
		}
		goto out_unlock_bh;
	}

	set_buffer_jbddirty(bh);

	/*
	 * Metadata already on the current transaction list doesn't
	 * need to be filed.  Metadata on another transaction's list must
	 * be committing, and will be refiled once the commit completes:
	 * leave it alone for now.
	 * 
	 * 已经在当前事务列表上的元数据不需要归档。另一个事务列表上的元数据必须是 committing 的，
	 * 并且一旦提交完成，将重新归档：现在就让它保持不变。
	 */
	// jh->b_transaction != transaction（handle->h_transaction）: buffer不在当前事务中
	if (jh->b_transaction != transaction) {
		JBUFFER_TRACE(jh, "already on other transaction");
		// buffer不在当前committing事务中或buffer的next_transaction不是当前事务
		// 这就是出问题了，也即我们用的是其他事务的buffer，报错
		if (unlikely(((jh->b_transaction !=
			       journal->j_committing_transaction)) ||
			     (jh->b_next_transaction != transaction))) {
			printk(KERN_ERR "jbd2_journal_dirty_metadata: %s: "
			       "bad jh for block %llu: "
			       "transaction (%p, %u), "
			       "jh->b_transaction (%p, %u), "
			       "jh->b_next_transaction (%p, %u), jlist %u\n",
			       journal->j_devname,
			       (unsigned long long) bh->b_blocknr,
			       transaction, transaction->t_tid,
			       jh->b_transaction,
			       jh->b_transaction ?
			       jh->b_transaction->t_tid : 0,
			       jh->b_next_transaction,
			       jh->b_next_transaction ?
			       jh->b_next_transaction->t_tid : 0,
			       jh->b_jlist);
			WARN_ON(1);
			ret = -EINVAL;
		}
		/* And this case is illegal: we can't reuse another
		 * transaction's data buffer, ever. 
		 * 
		 * 这种情况是非法的：我们永远不能重用另一个事务的数据缓冲区。
		 */
		goto out_unlock_bh;
	}

	/* That test should have eliminated the following case: */
	J_ASSERT_JH(jh, jh->b_frozen_data == NULL);

	JBUFFER_TRACE(jh, "file as BJ_Metadata");
	spin_lock(&journal->j_list_lock);
	// 将jh对应的buffer添加到transaction->t_buffers列表(BJ_Metadata)中
	__jbd2_journal_file_buffer(jh, transaction, BJ_Metadata);
	spin_unlock(&journal->j_list_lock);
out_unlock_bh:
	spin_unlock(&jh->b_state_lock);
out:
	JBUFFER_TRACE(jh, "exit");
	return ret;
}

/**
 * jbd2_journal_forget() - bforget() for potentially-journaled buffers.
 * @handle: transaction handle
 * @bh:     bh to 'forget'
 *
 * We can only do the bforget if there are no commits pending against the
 * buffer.  If the buffer is dirty in the current running transaction we
 * can safely unlink it.
 *
 * 在事务句柄handle上为可能被journal的缓冲区bh执行 bforget()。
 * 
 * 只有在缓冲区中没有待处理的提交时，我们才能执行bforget操作。如果缓冲区在当前运行的事务中是脏的，
 * 我们可以安全地unlink它。
 * 
 * 
 * bh may not be a journalled buffer at all - it may be a non-JBD
 * buffer which came off the hashtable.  Check for this.
 *
 * Decrements bh->b_count by one.
 *
 * Allow this call even if the handle has aborted --- it may be part of
 * the caller's cleanup after an abort.
 * 
 * bh可能根本不是一个日志化的缓冲区 - 它可能是一个来自散列表的非JBD缓冲区。检查这一点。
 * 将bh->b_count减1。
 * 即使句柄已中止，也允许此调用 - 它可能是调用者在中止后进行清理的一部分。
 */
int jbd2_journal_forget(handle_t *handle, struct buffer_head *bh)
{
	transaction_t *transaction = handle->h_transaction;
	journal_t *journal;
	struct journal_head *jh;
	int drop_reserve = 0;
	int err = 0;
	int was_modified = 0;

	if (is_handle_aborted(handle))
		return -EROFS;
	journal = transaction->t_journal;

	BUFFER_TRACE(bh, "entry");

	jh = jbd2_journal_grab_journal_head(bh);
	if (!jh) {
		__bforget(bh);
		return 0;
	}

	spin_lock(&jh->b_state_lock);

	/* Critical error: attempting to delete a bitmap buffer, maybe?
	 * Don't do any jbd operations, and return an error. */
	if (!J_EXPECT_JH(jh, !jh->b_committed_data,
			 "inconsistent data on disk")) {
		err = -EIO;
		goto drop;
	}

	/* keep track of whether or not this transaction modified us */
	was_modified = jh->b_modified;

	/*
	 * The buffer's going from the transaction, we must drop
	 * all references -bzzz
	 */
	jh->b_modified = 0;

	// 该buffer属于当前事务
	if (jh->b_transaction == transaction) {
		J_ASSERT_JH(jh, !jh->b_frozen_data);

		/* If we are forgetting a buffer which is already part
		 * of this transaction, then we can just drop it from
		 * the transaction immediately.
		 * 
		 * 如果我们正在忘记一个已经是该事务一部分的缓冲区，那么我们可以立即将其从事务中删除。
		 */
		clear_buffer_dirty(bh);
		clear_buffer_jbddirty(bh);

		JBUFFER_TRACE(jh, "belongs to current transaction: unfile");

		/*
		 * we only want to drop a reference if this transaction
		 * modified the buffer
		 * 
		 * 我们只想在该事务修改了缓冲区时才删除引用
		 */
		if (was_modified)
			drop_reserve = 1;

		/*
		 * We are no longer going to journal this buffer.
		 * However, the commit of this transaction is still
		 * important to the buffer: the delete that we are now
		 * processing might obsolete an old log entry, so by
		 * committing, we can satisfy the buffer's checkpoint.
		 *
		 * So, if we have a checkpoint on the buffer, we should
		 * now refile the buffer on our BJ_Forget list so that
		 * we know to remove the checkpoint after we commit.
		 * 
		 * 我们不再记录该缓冲区。但是，该事务的提交对缓冲区仍然很重要：
		 * 我们现在正在处理的删除可能会使旧的日志条目过时， 因此通过提交，
		 * 我们可以满足缓冲区的检查点。
		 * 
		 * 因此，如果我们在缓冲区上有一个检查点，我们现在应该将缓冲区重新放在BJ_Forget列表上，
		 * 以便我们知道在提交后删除检查点。
		 * TODO: WHAT THE FA?
		 */

		spin_lock(&journal->j_list_lock);
		// if成功：该buffer有检查点，将jh从jh链表中移除，并将jh放入BJ_Forget列表中
		if (jh->b_cp_transaction) {
			// 从合适的事务列表中删除一个buffer
			__jbd2_journal_temp_unlink_buffer(jh);
			// 将jh放入事务的t_forget列表中
			__jbd2_journal_file_buffer(jh, transaction, BJ_Forget);
		} else {
			// 根据下面函数中的断言，这时jh->b_trans非NULL，jh->b_next_trans为NULL
			// 从所有事务中删除buffer，并移除jh指向其所属事务的指针jh->b_transaction
			__jbd2_journal_unfile_buffer(jh);
			// 当前事务的jh也不要了
			jbd2_journal_put_journal_head(jh);
		}
		spin_unlock(&journal->j_list_lock);
	} else if (jh->b_transaction) {
		// jh属于某个事务中，但不是此更新的事务(handle->h_transaction)；
		// 因此jh只能属于该journal的（上一个同时存在的）committing事务
		// 说上一个是因为当前更新在下一个running事务中
		J_ASSERT_JH(jh, (jh->b_transaction ==
				 journal->j_committing_transaction));
		/* However, if the buffer is still owned by a prior
		 * (committing) transaction, we can't drop it yet... */
		JBUFFER_TRACE(jh, "belongs to older transaction");
		/* ... but we CAN drop it from the new transaction through
		 * marking the buffer as freed and set j_next_transaction to
		 * the new transaction, so that not only the commit code
		 * knows it should clear dirty bits when it is done with the
		 * buffer, but also the buffer can be checkpointed only
		 * after the new transaction commits. */

		set_buffer_freed(bh);

		if (!jh->b_next_transaction) {
			spin_lock(&journal->j_list_lock);
			jh->b_next_transaction = transaction;
			spin_unlock(&journal->j_list_lock);
		} else {
			J_ASSERT(jh->b_next_transaction == transaction);

			/*
			 * only drop a reference if this transaction modified
			 * the buffer
			 */
			if (was_modified)
				drop_reserve = 1;
		}
	} else {
		/*
		 * Finally, if the buffer is not belongs to any
		 * transaction, we can just drop it now if it has no
		 * checkpoint.
		 * 
		 * 最后，如果缓冲区不属于任何事务。
		 * 那么如果它没有检查点，我们现在可以将其删除。
		 */
		spin_lock(&journal->j_list_lock);
		if (!jh->b_cp_transaction) {
			JBUFFER_TRACE(jh, "belongs to none transaction");
			spin_unlock(&journal->j_list_lock);
			goto drop;
		}

		/*
		 * Otherwise, if the buffer has been written to disk,
		 * it is safe to remove the checkpoint and drop it.
		 * 
		 * 否则，如果缓冲区已写入磁盘，则可以安全地删除检查点并将其删除。
		 */
		if (!buffer_dirty(bh)) {
			__jbd2_journal_remove_checkpoint(jh);
			spin_unlock(&journal->j_list_lock);
			goto drop;
		}

		/*
		 * The buffer is still not written to disk, we should
		 * attach this buffer to current transaction so that the
		 * buffer can be checkpointed only after the current
		 * transaction commits.
		 * 
		 * 缓冲区仍未写入磁盘，我们应将此缓冲区附加到当前事务，
		 * 以便在当前事务提交后才能对缓冲区进行检查点。
		 */
		clear_buffer_dirty(bh);
		__jbd2_journal_file_buffer(jh, transaction, BJ_Forget);
		spin_unlock(&journal->j_list_lock);
	}
drop:
	__brelse(bh);
	spin_unlock(&jh->b_state_lock);
	jbd2_journal_put_journal_head(jh);
	if (drop_reserve) {
		/* no need to reserve log space for this block -bzzz */
		handle->h_total_credits++;
	}
	return err;
}

/**
 * jbd2_journal_stop() - complete a transaction
 * @handle: transaction to complete.
 *
 * All done for a particular handle.
 *
 * There is not much action needed here.  We just return any remaining
 * buffer credits to the transaction and remove the handle.  The only
 * complication is that we need to start a commit operation if the
 * filesystem is marked for synchronous update.
 *
 * jbd2_journal_stop itself will not usually return an error, but it may
 * do so in unusual circumstances.  In particular, expect it to
 * return -EIO if a jbd2_journal_abort has been executed since the
 * transaction began.
 * 
 * 这里不需要太多的操作。我们只需将任何剩余的缓冲区信用额归还给事务并删除句柄。
 * 唯一的复杂之处在于，如果文件系统标记为同步更新，则需要启动提交操作。
 * 
 * jbd2_journal_stop本身通常不会返回错误，但在不寻常的情况下可能会这样做。
 * 特别是，如果自事务开始以来执行了jbd2_journal_abort，则期望它返回-EIO。
 */
int jbd2_journal_stop(handle_t *handle)
{
	transaction_t *transaction = handle->h_transaction;
	journal_t *journal;
	int err = 0, wait_for_commit = 0;
	tid_t tid;
	pid_t pid;

	if (--handle->h_ref > 0) {
		jbd2_debug(4, "h_ref %d -> %d\n", handle->h_ref + 1,
						 handle->h_ref);
		if (is_handle_aborted(handle))
			return -EIO;
		return 0;
	}
	if (!transaction) {
		/*
		 * Handle is already detached from the transaction so there is
		 * nothing to do other than free the handle.
		 * 
		 * 句柄已从事务中分离，因此除了释放句柄外，无需执行其他操作。
		 */
		memalloc_nofs_restore(handle->saved_alloc_context);
		goto free_and_exit;
	}
	journal = transaction->t_journal;
	tid = transaction->t_tid;

	if (is_handle_aborted(handle))
		err = -EIO;

	jbd2_debug(4, "Handle %p going down\n", handle);
	trace_jbd2_handle_stats(journal->j_fs_dev->bd_dev,
				tid, handle->h_type, handle->h_line_no,
				jiffies - handle->h_start_jiffies,
				handle->h_sync, handle->h_requested_credits,
				(handle->h_requested_credits -
				 handle->h_total_credits));

	/*
	 * Implement synchronous transaction batching.  If the handle
	 * was synchronous, don't force a commit immediately.  Let's
	 * yield and let another thread piggyback onto this
	 * transaction.  Keep doing that while new threads continue to
	 * arrive.  It doesn't cost much - we're about to run a commit
	 * and sleep on IO anyway.  Speeds up many-threaded, many-dir
	 * operations by 30x or more...
	 * 
	 * 实现同步事务批处理。如果句柄是同步的，则不要立即强制提交。
	 * 让我们 yield 并让另一个线程搭便车到这个事务。在新线程不断到达的同时继续这样做。
	 * 它的成本并不高 -- 不管怎样，我们都将要运行一次提交并在IO上休眠。
	 * 将多线程，多dir操作速度提高30倍或更多。。。
	 *
	 * We try and optimize the sleep time against what the
	 * underlying disk can do, instead of having a static sleep
	 * time.  This is useful for the case where our storage is so
	 * fast that it is more optimal to go ahead and force a flush
	 * and wait for the transaction to be committed than it is to
	 * wait for an arbitrary amount of time for new writers to
	 * join the transaction.  We achieve this by measuring how
	 * long it takes to commit a transaction, and compare it with
	 * how long this transaction has been running, and if run time
	 * < commit time then we sleep for the delta and commit.  This
	 * greatly helps super fast disks that would see slowdowns as
	 * more threads started doing fsyncs.
	 * 
	 * 我们尝试根据底层磁盘的实际情况来优化睡眠时间，而不是有一个静态的睡眠时间。
	 * 这对于我们的存储速度非常快的情况非常有用，因为强制刷新并等待事务提交比
	 * 等待任意时间让新的写入者加入事务更加优化。我们通过测量提交事务所需的时间并
	 * 将其与事务已运行的时间进行比较来实现这一点，如果运行时间 < 提交时间，
	 * 那么我们将睡眠时间差并提交。这极大地帮助了超快速的磁盘，当更多线程开始执行fsync时，
	 * 超高速磁盘会变慢。
	 * TODO: 重要，我要研究的，同时提交的事务线程数？
	 *
	 * But don't do this if this process was the most recent one
	 * to perform a synchronous write.  We do this to detect the
	 * case where a single process is doing a stream of sync
	 * writes.  No point in waiting for joiners in that case.
	 * 
	 * 但是，如果此进程是最近执行同步写入的进程，则不要这样做。
	 * 我们这样做是为了检测单个进程正在执行同步写入流的情况。
	 * 在这种情况下，等待加入者是没有意义的。
	 *
	 * Setting max_batch_time to 0 disables this completely.
	 */
	pid = current->pid;
	if (handle->h_sync && journal->j_last_sync_writer != pid &&
	    journal->j_max_batch_time) {
		u64 commit_time, trans_time;

		journal->j_last_sync_writer = pid;

		read_lock(&journal->j_state_lock);
		commit_time = journal->j_average_commit_time;
		read_unlock(&journal->j_state_lock);

		trans_time = ktime_to_ns(ktime_sub(ktime_get(),
						   transaction->t_start_time));

		commit_time = max_t(u64, commit_time,
				    1000*journal->j_min_batch_time);
		commit_time = min_t(u64, commit_time,
				    1000*journal->j_max_batch_time);

		if (trans_time < commit_time) {
			ktime_t expires = ktime_add_ns(ktime_get(),
						       commit_time);
			set_current_state(TASK_UNINTERRUPTIBLE);
			schedule_hrtimeout(&expires, HRTIMER_MODE_ABS);
		}
	}

	if (handle->h_sync)
		transaction->t_synchronous_commit = 1;

	/*
	 * If the handle is marked SYNC, we need to set another commit
	 * going!  We also want to force a commit if the transaction is too
	 * old now.
	 * 
	 * 如果句柄标记为SYNC，则需要设置另一个提交！
	 * 如果事务现在太旧，则还要强制提交。
	 */
	if (handle->h_sync ||
	    time_after_eq(jiffies, transaction->t_expires)) {
		/* Do this even for aborted journals: an abort still
		 * completes the commit thread, it just doesn't write
		 * anything to disk. */

		jbd2_debug(2, "transaction too old, requesting commit for "
					"handle %p\n", handle);
		/* This is non-blocking */
		// 提交tid事务，该事务多半是journal的running transaction
		jbd2_log_start_commit(journal, tid);

		/*
		 * Special case: JBD2_SYNC synchronous updates require us
		 * to wait for the commit to complete.
		 * 
		 * 特殊情况：JBD2_SYNC同步更新要求我们等待提交完成。
		 */
		if (handle->h_sync && !(current->flags & PF_MEMALLOC))
			wait_for_commit = 1;
	}

	/*
	 * Once stop_this_handle() drops t_updates, the transaction could start
	 * committing on us and eventually disappear.  So we must not
	 * dereference transaction pointer again after calling
	 * stop_this_handle().
	 * 
	 * 一旦stop_this_handle()释放了t_updates，事务就可以开始提交我们，并最终消失。
	 * 因此，在调用stop_this_handle()之后，我们不能再次引用事务指针。
	 */
	stop_this_handle(handle);

	if (wait_for_commit)
		err = jbd2_log_wait_commit(journal, tid);

free_and_exit:
	if (handle->h_rsv_handle)
		jbd2_free_handle(handle->h_rsv_handle);
	jbd2_free_handle(handle);
	return err;
}

/*
 *
 * List management code snippets: various functions for manipulating the
 * transaction buffer lists.
 * 
 * 列表管理代码片段：用于操作事务缓冲区列表的各种函数。
 */

/*
 * Append a buffer to a transaction list, given the transaction's list head
 * pointer.
 *
 * j_list_lock is held.
 *
 * jh->b_state_lock is held.
 */

static inline void
__blist_add_buffer(struct journal_head **list, struct journal_head *jh)
{
	if (!*list) {
		jh->b_tnext = jh->b_tprev = jh;
		*list = jh;
	} else {
		/* Insert at the tail of the list to preserve order */
		struct journal_head *first = *list, *last = first->b_tprev;
		jh->b_tprev = last;
		jh->b_tnext = first;
		last->b_tnext = first->b_tprev = jh;
	}
}

/*
 * Remove a buffer from a transaction list, given the transaction's list
 * head pointer.
 *
 * Called with j_list_lock held, and the journal may not be locked.
 *
 * jh->b_state_lock is held.
 * 
 * 从一个事务列表中删除一个buffer，给定事务的列表头指针。
 * 在持有j_list_lock的情况下调用，日志可能没有被锁定。
 * jh->b_state_lock被持有。
 */

static inline void
__blist_del_buffer(struct journal_head **list, struct journal_head *jh)
{
	if (*list == jh) {
		*list = jh->b_tnext;
		if (*list == jh)
			*list = NULL;
	}
	jh->b_tprev->b_tnext = jh->b_tnext;
	jh->b_tnext->b_tprev = jh->b_tprev;
}

/*
 * Remove a buffer from the appropriate transaction list.
 *
 * Note that this function can *change* the value of
 * bh->b_transaction->t_buffers, t_forget, t_shadow_list, t_log_list or
 * t_reserved_list.  If the caller is holding onto a copy of one of these
 * pointers, it could go bad.  Generally the caller needs to re-read the
 * pointer from the transaction_t.
 *
 * Called under j_list_lock.
 * 
 * 从该buffer所属事务（jh->btransaction）的相应列表（根据jh->b_jlist判断）中
 * 删除该buffer自身
 * 
 * 注意，这个函数可以改变bh->b_transaction->t_buffers, t_forget, t_shadow_list,
 *  t_log_list或t_reserved_list的值。如果调用者持有这些指针之一的副本，它可能会出错。
 * 通常，调用者需要从transaction_t中重新读取指针。
 */
static void __jbd2_journal_temp_unlink_buffer(struct journal_head *jh)
{
	struct journal_head **list = NULL;
	transaction_t *transaction;
	struct buffer_head *bh = jh2bh(jh);

	lockdep_assert_held(&jh->b_state_lock);
	transaction = jh->b_transaction;
	if (transaction)
		assert_spin_locked(&transaction->t_journal->j_list_lock);

	J_ASSERT_JH(jh, jh->b_jlist < BJ_Types);
	if (jh->b_jlist != BJ_None)
		J_ASSERT_JH(jh, transaction != NULL);

	switch (jh->b_jlist) {
	case BJ_None:	// NOT journaled
		return;
	case BJ_Metadata:	// 正常journaled元数据
		transaction->t_nr_buffers--;
		J_ASSERT_JH(jh, transaction->t_nr_buffers >= 0);
		list = &transaction->t_buffers;
		break;
	case BJ_Forget:	// 被此事务取代的缓冲区
		list = &transaction->t_forget;
		break;
	case BJ_Shadow:	// 缓冲区内容被隐藏到log中
		list = &transaction->t_shadow_list;
		break;
	case BJ_Reserved:	// 缓冲区被保留以供journal访问
		list = &transaction->t_reserved_list;
		break;
	}

	__blist_del_buffer(list, jh);
	// jh被从事务列表（别管是哪个列表吧）中删除，变回not journaled状态
	jh->b_jlist = BJ_None;
	if (transaction && is_journal_aborted(transaction->t_journal))
		clear_buffer_jbddirty(bh);
	else if (test_clear_buffer_jbddirty(bh))
		mark_buffer_dirty(bh);	/* Expose it to the VM */
}

/*
 * Remove buffer from all transactions. The caller is responsible for dropping
 * the jh reference that belonged to the transaction.
 *
 * Called with bh_state lock and j_list_lock
 * 
 * 从所有事务中删除buffer。调用者负责删除属于事务的jh引用（即指向其所属事务的指针jh->b_transaction）。
 * 在bh_state lock和j_list_lock中调用
 */
static void __jbd2_journal_unfile_buffer(struct journal_head *jh)
{
	J_ASSERT_JH(jh, jh->b_transaction != NULL);
	J_ASSERT_JH(jh, jh->b_next_transaction == NULL);

	__jbd2_journal_temp_unlink_buffer(jh);
	jh->b_transaction = NULL;
}

void jbd2_journal_unfile_buffer(journal_t *journal, struct journal_head *jh)
{
	struct buffer_head *bh = jh2bh(jh);

	/* Get reference so that buffer cannot be freed before we unlock it */
	get_bh(bh);
	spin_lock(&jh->b_state_lock);
	spin_lock(&journal->j_list_lock);
	__jbd2_journal_unfile_buffer(jh);
	spin_unlock(&journal->j_list_lock);
	spin_unlock(&jh->b_state_lock);
	jbd2_journal_put_journal_head(jh);
	__brelse(bh);
}

/*
 * Called from jbd2_journal_try_to_free_buffers().
 *
 * Called under jh->b_state_lock
 */
static void
__journal_try_to_free_buffer(journal_t *journal, struct buffer_head *bh)
{
	struct journal_head *jh;

	jh = bh2jh(bh);

	if (buffer_locked(bh) || buffer_dirty(bh))
		goto out;

	if (jh->b_next_transaction != NULL || jh->b_transaction != NULL)
		goto out;

	spin_lock(&journal->j_list_lock);
	if (jh->b_cp_transaction != NULL) {
		/* written-back checkpointed metadata buffer */
		JBUFFER_TRACE(jh, "remove from checkpoint list");
		__jbd2_journal_remove_checkpoint(jh);
	}
	spin_unlock(&journal->j_list_lock);
out:
	return;
}

/**
 * jbd2_journal_try_to_free_buffers() - try to free page buffers.
 * @journal: journal for operation
 * @folio: Folio to detach data from.
 *
 * For all the buffers on this page,
 * if they are fully written out ordered data, move them onto BUF_CLEAN
 * so try_to_free_buffers() can reap them.
 * 
 * 对于此页上的所有缓冲区，如果它们是完全写出的有序数据，则将它们移动到BUF_CLEAN，
 * 以便try_to_free_buffers()可以收割它们。
 *
 * This function returns non-zero if we wish try_to_free_buffers()
 * to be called. We do this if the page is releasable by try_to_free_buffers().
 * We also do it if the page has locked or dirty buffers and the caller wants
 * us to perform sync or async writeout.
 * 
 * 如果我们希望调用try_to_free_buffers()，则此函数返回非零值。
 * 如果页面可以通过try_to_free_buffers()释放，则我们这样做。
 * 如果页面具有锁定或脏缓冲区，并且调用者希望我们执行同步或异步写出，则我们也会这样做。
 *
 * This complicates JBD locking somewhat.  We aren't protected by the
 * BKL here.  We wish to remove the buffer from its committing or
 * running transaction's ->t_datalist via __jbd2_journal_unfile_buffer.
 * 
 * 这使得JBD锁定有些复杂。我们在这里不受BKL的保护。
 * 我们希望通过__jbd2_journal_unfile_buffer从其提交或运行事务的->t_datalist中删除缓冲区。
 *
 * This may *change* the value of transaction_t->t_datalist, so anyone
 * who looks at t_datalist needs to lock against this function.
 * 
 * 这可能会更改transaction_t->t_datalist的值，
 * 因此任何查看t_datalist的人都需要针对此函数进行锁定。
 *
 * Even worse, someone may be doing a jbd2_journal_dirty_data on this
 * buffer.  So we need to lock against that.  jbd2_journal_dirty_data()
 * will come out of the lock with the buffer dirty, which makes it
 * ineligible for release here.
 * 
 * 更糟糕的是，有人可能正在对此缓冲区执行jbd2_journal_dirty_data。
 * 因此，我们需要针对此进行锁定。jbd2_journal_dirty_data()将从锁中出来，
 * 缓冲区变脏，这使其不适合在此处释放。
 *
 * Who else is affected by this?  hmm...  Really the only contender
 * is do_get_write_access() - it could be looking at the buffer while
 * journal_try_to_free_buffer() is changing its state.  But that
 * cannot happen because we never reallocate freed data as metadata
 * while the data is part of a transaction.  Yes?
 * 
 * 还有谁受到这个的影响？hmm...真正的唯一竞争者是do_get_write_access()，
 * 它可能在journal_try_to_free_buffer()更改其状态时查看缓冲区。
 * 但是这是不可能的，因为我们在数据是事务的一部分时，从不将释放的数据重新分配为元数据。
 * 是的？
 *
 * Return false on failure, true on success
 */
bool jbd2_journal_try_to_free_buffers(journal_t *journal, struct folio *folio)
{
	struct buffer_head *head;
	struct buffer_head *bh;
	bool ret = false;

	J_ASSERT(folio_test_locked(folio));

	head = folio_buffers(folio);
	bh = head;
	do {
		struct journal_head *jh;

		/*
		 * We take our own ref against the journal_head here to avoid
		 * having to add tons of locking around each instance of
		 * jbd2_journal_put_journal_head().
		 * 
		 * 我们在这里针对journal_head采取自己的引用，
		 * 以避免在每个 jbd2_journal_put_journal_head() 实例周围添加大量锁定。
		 */
		jh = jbd2_journal_grab_journal_head(bh);
		if (!jh)
			continue;

		spin_lock(&jh->b_state_lock);
		__journal_try_to_free_buffer(journal, bh);
		spin_unlock(&jh->b_state_lock);
		jbd2_journal_put_journal_head(jh);
		if (buffer_jbd(bh))
			goto busy;
	} while ((bh = bh->b_this_page) != head);

	ret = try_to_free_buffers(folio);
busy:
	return ret;
}

/*
 * This buffer is no longer needed.  If it is on an older transaction's
 * checkpoint list we need to record it on this transaction's forget list
 * to pin this buffer (and hence its checkpointing transaction) down until
 * this transaction commits.  If the buffer isn't on a checkpoint list, we
 * release it.
 * Returns non-zero if JBD no longer has an interest in the buffer.
 *
 * 销毁缓冲区...
 * 
 * 该缓冲区不再被需要。如果它在旧事务的检查点列表上，我们需要在传入（当前）事务的忘记列表上记录它，
 * 以将此缓冲区（因此其检查点事务）pin到此事务提交为止。
 * 如果该缓冲区不在检查点列表上，我们将其释放。
 * 
 * Called under j_list_lock.
 *
 * Called under jh->b_state_lock.
 */
static int __dispose_buffer(struct journal_head *jh, transaction_t *transaction)
{
	int may_free = 1;
	struct buffer_head *bh = jh2bh(jh);

	if (jh->b_cp_transaction) {
		JBUFFER_TRACE(jh, "on running+cp transaction");
		// 从该buffer所属事务（jh->btransaction）的相应列表（根据jh->b_jlist判断）中
		// 删除该buffer自身
		__jbd2_journal_temp_unlink_buffer(jh);
		/*
		 * We don't want to write the buffer anymore, clear the
		 * bit so that we don't confuse checks in
		 * __journal_file_buffer
		 */
		clear_buffer_dirty(bh);
		__jbd2_journal_file_buffer(jh, transaction, BJ_Forget);
		may_free = 0;
	} else {
		JBUFFER_TRACE(jh, "on running transaction");
		__jbd2_journal_unfile_buffer(jh);
		jbd2_journal_put_journal_head(jh);
	}
	return may_free;
}

/*
 * jbd2_journal_invalidate_folio
 *
 * This code is tricky.  It has a number of cases to deal with.
 *
 * There are two invariants which this code relies on:
 * 
 * 1）i_size必须在我们开始调用invalidate_folio之前在磁盘上更新。
 *
 * i_size must be updated on disk before we start calling invalidate_folio
 * on the data.
 *
 *  This is done in ext3 by defining an ext3_setattr method which
 *  updates i_size before truncate gets going.  By maintaining this
 *  invariant, we can be sure that it is safe to throw away any buffers
 *  attached to the current transaction: once the transaction commits,
 *  we know that the data will not be needed.
 * 
 * 这在ext3中通过定义一个ext3_setattr方法来完成，该方法在截断开始之前更新i_size。
 * 通过保持这个不变量，我们可以确保可以安全地丢弃附加到当前事务的任何缓冲区：
 * 一旦事务提交，我们就知道不再需要数据。
 * TODO: WHAT IS 这几大段注释 TALKING ABOUT?明天看一下再。
 *
 *  Note however that we can *not* throw away data belonging to the
 *  previous, committing transaction!
 * 
 * 但是请注意，我们不能丢弃属于先前提交的事务的数据！
 *
 * 2) 作为先前提交事务一部分的任何磁盘块（因此不能立即丢弃）不会在新的运行事务中重用
 * 
 * Any disk blocks which *are* part of the previous, committing
 * transaction (and which therefore cannot be discarded immediately) are
 * not going to be reused in the new running transaction
 *
 *  The bitmap committed_data images guarantee this: any block which is
 *  allocated in one transaction and removed in the next will be marked
 *  as in-use in the committed_data bitmap, so cannot be reused until
 *  the next transaction to delete the block commits.  This means that
 *  leaving committing buffers dirty is quite safe: the disk blocks
 *  cannot be reallocated to a different file and so buffer aliasing is
 *  not possible.
 * 
 * 位图 committed_data image保证了这一点：在一个事务中分配并在下一个事务中删除的任何块
 * 都将在committed_data位图中被标记为使用中，因此在下一个删除该块的事务提交之前不能
 * 重新使用。这意味着保留提交缓冲区是非常安全的：磁盘块不能被重新分配给不同的文件，
 * 因此缓冲区别名是不可能的。
 *
 * The above applies mainly to ordered data mode.  In writeback mode we
 * don't make guarantees about the order in which data hits disk --- in
 * particular we don't guarantee that new dirty data is flushed before
 * transaction commit --- so it is always safe just to discard data
 * immediately in that mode.  --sct
 * 
 * 上述主要适用于有序数据模式。在回写模式下，我们不保证数据到达磁盘的顺序——特别是我们不保证
 * 在事务提交之前刷新新的脏数据——因此在该模式下立即丢弃数据总是安全的。--sct
 */

/*
 * The journal_unmap_buffer helper function returns zero if the buffer
 * concerned remains pinned as an anonymous buffer belonging to an older
 * transaction.
 * 
 * 如果相关的缓冲区仍然作为属于旧事务的匿名缓冲区固定，则journal_unmap_buffer辅助函数返回零。
 *
 * We're outside-transaction here.  Either or both of j_running_transaction
 * and j_committing_transaction may be NULL.
 * 
 * 我们在事务之外。j_running_transaction和j_committing_transaction可能是NULL。
 */
static int journal_unmap_buffer(journal_t *journal, struct buffer_head *bh,
				int partial_page)
{
	transaction_t *transaction;
	struct journal_head *jh;
	int may_free = 1;

	BUFFER_TRACE(bh, "entry");

	/*
	 * It is safe to proceed here without the j_list_lock because the
	 * buffers cannot be stolen by try_to_free_buffers as long as we are
	 * holding the page lock. --sct
	 * 
	 * 在没有j_list_lock的情况下继续进行是安全的，因为只要我们持有页面锁，
	 * 缓冲区就不能被try_to_free_buffers窃取。--sct
	 */

	jh = jbd2_journal_grab_journal_head(bh);
	if (!jh)
		goto zap_buffer_unlocked;

	/* OK, we have data buffer in journaled mode */
	write_lock(&journal->j_state_lock);
	spin_lock(&jh->b_state_lock);
	spin_lock(&journal->j_list_lock);

	/*
	 * We cannot remove the buffer from checkpoint lists until the
	 * transaction adding inode to orphan list (let's call it T)
	 * is committed.  Otherwise if the transaction changing the
	 * buffer would be cleaned from the journal before T is
	 * committed, a crash will cause that the correct contents of
	 * the buffer will be lost.  On the other hand we have to
	 * clear the buffer dirty bit at latest at the moment when the
	 * transaction marking the buffer as freed in the filesystem
	 * structures is committed because from that moment on the
	 * block can be reallocated and used by a different page.
	 * Since the block hasn't been freed yet but the inode has
	 * already been added to orphan list, it is safe for us to add
	 * the buffer to BJ_Forget list of the newest transaction.
	 * 
	 * 在 将inode添加到孤立列表 的事务（我们称之为T）提交之前，我们不能将缓冲区从检查点列表中删除。
	 * 否则，如果在T提交之前将 更改缓冲区的事务 从日志中清除，则崩溃将导致缓冲区的正确内容丢失。
	 
	 * 注：意思是 *inode添加到孤立列表* 提交之前，要是发生崩溃，文件系统回退到的是inode未删除的版本，
	 * 旧版本这个时候是需要在的。
	 * 
	 * 另一方面，我们必须在 在文件系统结构中-将缓冲区标记为已释放 的事务提交时最迟清除缓冲区脏位，
	 * 因为从那时起，该块可以被重新分配并由不同的页面使用。由于该块尚未被释放，但是inode已经被
	 * 添加到孤立列表中，因此我们可以将缓冲区添加到最新事务的BJ_Forget列表中。
	 *
	 * 注：意思是说 *文件系统中将缓冲区标记为已释放* 提交后，随时可能分配缓冲区给其他文件了，
	 * 这个时候必须要保证缓冲区已经是可用的了。
	 * 
	 * 整个时间线：inode添加到孤立列表 ->| 将缓冲区从检查点列表中删除；
	 * 			清除缓冲区脏位 ->| 文件系统结构中-将缓冲区标记为已释放。
	 * 
	 * Also we have to clear buffer_mapped flag of a truncated buffer
	 * because the buffer_head may be attached to the page straddling
	 * i_size (can happen only when blocksize < pagesize) and thus the
	 * buffer_head can be reused when the file is extended again. So we end
	 * up keeping around invalidated buffers attached to transactions'
	 * BJ_Forget list just to stop checkpointing code from cleaning up
	 * the transaction this buffer was modified in.
	 * 
	 * 此外，我们必须清除 已被截断缓冲区 的buffer_mapped标志，因为buffer_head可能附加到
	 * 跨越i_size的页面（仅当blocksize < pagesize时才会发生），因此当文件再次扩展时，可以
	 * 重用buffer_head。因此，我们最终保留了附加到事务的BJ_Forget列表的无效缓冲区，以阻止
	 * 检查点代码清除修改此缓冲区的事务。
	 */
	transaction = jh->b_transaction;
	if (transaction == NULL) {
		/* First case: not on any transaction.  If it
		 * has no checkpoint link, then we can zap it:
		 * it's a writeback-mode buffer so we don't care
		 * if it hits disk safely. 
		 * 
		 * 第一种情况：jh不在任何running或committing事务中。
		 * 如果jh也不在检查点事务中（没有指向检查点事务的链接），那么我们可以将其删除：
		 * 它是一个写回模式缓冲区，因此我们不关心它是否安全地命中磁盘。
		 * */
		if (!jh->b_cp_transaction) {
			JBUFFER_TRACE(jh, "not on any transaction: zap");
			goto zap_buffer;
		}

		// 第二种情况：有检查点链接，在某个检查点事务里面：从检查点列表中删除
		if (!buffer_dirty(bh)) {
			/* bdflush has written it.  We can drop it now */
			__jbd2_journal_remove_checkpoint(jh);
			goto zap_buffer;
		}

		/* OK, it must be in the journal but still not
		 * written fully to disk: it's metadata or
		 * journaled data... 
		 * 
		 * 好吧，它必须在日志中，但仍未完全写入磁盘：它是元数据或journaled数据...
		 * */

		if (journal->j_running_transaction) {
			// if判定成立，现在是有running trans的情况，running trans可以承接
			// 该缓冲区，所以将该缓冲区添加到running trans的BJ_Forget列表中

			/* ... and once the current transaction has
			 * committed, the buffer won't be needed any
			 * longer. 
			 * 
			 * ...一旦当前事务提交，就不再需要缓冲区。
			 * */
			JBUFFER_TRACE(jh, "checkpointed: add to BJ_Forget");
			may_free = __dispose_buffer(jh,
					journal->j_running_transaction);
			goto zap_buffer;
		} else {
			// TODO: 后两种情况，也即jh在journal的running或committing事务中时，
			// TODO: jh可以同时在一个checkpointting事务中吗，也即jh->b_cp_transaction非NULL?
			/* There is no currently-running transaction. So the
			 * orphan record which we wrote for this file must have
			 * passed into commit.  We must attach this buffer to
			 * the committing transaction, if it exists. 
			 * 
			 * 没有当前运行的事务。因此，我们为此文件编写的孤立记录必须已进入提交。
			 * 如果存在，我们必须将此缓冲区附加到提交事务。
			 * */
			if (journal->j_committing_transaction) {
				JBUFFER_TRACE(jh, "give to committing trans");
				may_free = __dispose_buffer(jh,
					journal->j_committing_transaction);
				goto zap_buffer;
			} else {
				/* The orphan record's transaction has
				 * committed.  We can cleanse this buffer 
				 *
				 * 孤立记录的事务已提交。我们可以清理此缓冲区
				 */
				clear_buffer_jbddirty(bh);
				__jbd2_journal_remove_checkpoint(jh);
				goto zap_buffer;
			}
		}
	} else if (transaction == journal->j_committing_transaction) {
		JBUFFER_TRACE(jh, "on committing transaction");
		/*
		 * The buffer is committing, we simply cannot touch
		 * it. If the page is straddling i_size we have to wait
		 * for commit and try again.
		 * 
		 * 缓冲区正在提交，我们根本不能触摸它。如果页面跨越i_size，我们必须等待提交并重试。
		 */
		if (partial_page) {
			spin_unlock(&journal->j_list_lock);
			spin_unlock(&jh->b_state_lock);
			write_unlock(&journal->j_state_lock);
			jbd2_journal_put_journal_head(jh);
			/* Already zapped buffer? Nothing to do... */
			if (!bh->b_bdev)
				return 0;
			return -EBUSY;
		}
		/*
		 * OK, buffer won't be reachable after truncate. We just clear
		 * b_modified to not confuse transaction credit accounting, and
		 * set j_next_transaction to the running transaction (if there
		 * is one) and mark buffer as freed so that commit code knows
		 * it should clear dirty bits when it is done with the buffer.
		 * 
		 * 注：第三行应为 set b_next_transaction blabla
		 * 
		 * 好吧，在截断后，缓冲区将不可访问。我们只是清除b_modified以不混淆事务信用记帐，
		 * 并将 jh->b_next_transaction 设置为journal->j_running_transaction
		 * （如果有的话），并将缓冲区标记为已释放，以便提交代码知道它在完成缓冲区后应清除脏位。
		 */
		set_buffer_freed(bh);
		if (journal->j_running_transaction && buffer_jbddirty(bh))
			jh->b_next_transaction = journal->j_running_transaction;
		jh->b_modified = 0;
		spin_unlock(&journal->j_list_lock);
		spin_unlock(&jh->b_state_lock);
		write_unlock(&journal->j_state_lock);
		jbd2_journal_put_journal_head(jh);
		return 0;
	} else {
		/* Good, the buffer belongs to the running transaction.
		 * We are writing our own transaction's data, not any
		 * previous one's, so it is safe to throw it away
		 * (remember that we expect the filesystem to have set
		 * i_size already for this truncate so recovery will not
		 * expose the disk blocks we are discarding here.) 
		 * 
		 * 好的，缓冲区属于正在运行的事务。我们正在写入自己事务的数据，而不是任何以前事务的，
		 * 因此可以安全地将其丢弃（请记住，我们期望文件系统已为此截断设置了i_size，
		 * 因此恢复不会暴露我们在此处丢弃的磁盘块。）
		 * */
		J_ASSERT_JH(jh, transaction == journal->j_running_transaction);
		JBUFFER_TRACE(jh, "on running transaction");
		may_free = __dispose_buffer(jh, transaction);
	}

zap_buffer:
	/*
	 * This is tricky. Although the buffer is truncated, it may be reused
	 * if blocksize < pagesize and it is attached to the page straddling
	 * EOF. Since the buffer might have been added to BJ_Forget list of the
	 * running transaction, journal_get_write_access() won't clear
	 * b_modified and credit accounting gets confused. So clear b_modified
	 * here.
	 */
	jh->b_modified = 0;
	spin_unlock(&journal->j_list_lock);
	spin_unlock(&jh->b_state_lock);
	write_unlock(&journal->j_state_lock);
	jbd2_journal_put_journal_head(jh);
zap_buffer_unlocked:
	clear_buffer_dirty(bh);
	J_ASSERT_BH(bh, !buffer_jbddirty(bh));
	clear_buffer_mapped(bh);
	clear_buffer_req(bh);
	clear_buffer_new(bh);
	clear_buffer_delay(bh);
	clear_buffer_unwritten(bh);
	bh->b_bdev = NULL;
	return may_free;
}

/**
 * jbd2_journal_invalidate_folio()
 * @journal: journal to use for flush...
 * @folio:    folio to flush
 * @offset:  start of the range to invalidate
 * @length:  length of the range to invalidate
 *
 * Reap page buffers containing data after in the specified range in page.
 * Can return -EBUSY if buffers are part of the committing transaction and
 * the page is straddling i_size. Caller then has to wait for current commit
 * and try again.
 * 
 * 在页面中指定范围后，收割包含数据的页面缓冲区。如果缓冲区是提交事务的一部分，
 * 并且页面跨越i_size，则可以返回-EBUSY。这种情况下线调用者必须等待当前提交，然后重试。
 */
int jbd2_journal_invalidate_folio(journal_t *journal, struct folio *folio,
				size_t offset, size_t length)
{
	struct buffer_head *head, *bh, *next;
	unsigned int stop = offset + length;
	unsigned int curr_off = 0;
	int partial_page = (offset || length < folio_size(folio));
	int may_free = 1;
	int ret = 0;

	if (!folio_test_locked(folio))
		BUG();
	head = folio_buffers(folio);
	if (!head)
		return 0;

	BUG_ON(stop > folio_size(folio) || stop < length);

	/* We will potentially be playing with lists other than just the
	 * data lists (especially for journaled data mode), so be
	 * cautious in our locking. 
	 * 
	 * 我们将潜在地使用除数据列表之外的其他列表（特别是对于日志数据模式），
	 * 因此在锁定时要小心。
	 * */

	bh = head;
	do {
		unsigned int next_off = curr_off + bh->b_size;
		next = bh->b_this_page;

		if (next_off > stop)
			return 0;

		if (offset <= curr_off) {
			/* This block is wholly outside the truncation point
			 * 
			 * 这个块完全在截断点之外
			 */
			lock_buffer(bh);
			ret = journal_unmap_buffer(journal, bh, partial_page);
			unlock_buffer(bh);
			if (ret < 0)
				return ret;
			may_free &= ret;
		}
		curr_off = next_off;
		bh = next;

	} while (bh != head);

	if (!partial_page) {
		if (may_free && try_to_free_buffers(folio))
			J_ASSERT(!folio_buffers(folio));
	}
	return 0;
}

/*
 * File a buffer on the given transaction list.
 * 归档一个缓冲区：根据jlist类型，将jh归档到transaction的特定链表中
 */
void __jbd2_journal_file_buffer(struct journal_head *jh,
			transaction_t *transaction, int jlist)
{
	struct journal_head **list = NULL;
	int was_dirty = 0;
	struct buffer_head *bh = jh2bh(jh);

	lockdep_assert_held(&jh->b_state_lock);
	assert_spin_locked(&transaction->t_journal->j_list_lock);

	J_ASSERT_JH(jh, jh->b_jlist < BJ_Types);
	J_ASSERT_JH(jh, jh->b_transaction == transaction ||
				jh->b_transaction == NULL);

	if (jh->b_transaction && jh->b_jlist == jlist)
		return;

	if (jlist == BJ_Metadata || jlist == BJ_Reserved ||
	    jlist == BJ_Shadow || jlist == BJ_Forget) {
		/*
		 * For metadata buffers, we track dirty bit in buffer_jbddirty
		 * instead of buffer_dirty. We should not see a dirty bit set
		 * here because we clear it in do_get_write_access but e.g.
		 * tune2fs can modify the sb and set the dirty bit at any time
		 * so we try to gracefully handle that.
		 * 
		 * 对于元数据缓冲区，我们跟踪buffer_jbddirty中的脏位，而不是buffer_dirty。
		 * 我们不应该在这里看到脏位设置，因为我们在do_get_write_access中清除它，
		 * 但是例如tune2fs可以随时修改sb并设置脏位，因此我们尝试优雅地处理它。
		 */
		if (buffer_dirty(bh))
			warn_dirty_buffer(bh);
		if (test_clear_buffer_dirty(bh) ||
		    test_clear_buffer_jbddirty(bh))
			was_dirty = 1;
	}

	if (jh->b_transaction)
		__jbd2_journal_temp_unlink_buffer(jh);
	else
		jbd2_journal_grab_journal_head(bh);
	jh->b_transaction = transaction;

	switch (jlist) {
	case BJ_None:
		J_ASSERT_JH(jh, !jh->b_committed_data);
		J_ASSERT_JH(jh, !jh->b_frozen_data);
		return;
	case BJ_Metadata:
		transaction->t_nr_buffers++;
		list = &transaction->t_buffers;
		break;
	case BJ_Forget:
		list = &transaction->t_forget;
		break;
	case BJ_Shadow:
		list = &transaction->t_shadow_list;
		break;
	case BJ_Reserved:
		list = &transaction->t_reserved_list;
		break;
	}

	__blist_add_buffer(list, jh);
	jh->b_jlist = jlist;

	if (was_dirty)
		set_buffer_jbddirty(bh);
}

void jbd2_journal_file_buffer(struct journal_head *jh,
				transaction_t *transaction, int jlist)
{
	spin_lock(&jh->b_state_lock);
	spin_lock(&transaction->t_journal->j_list_lock);
	__jbd2_journal_file_buffer(jh, transaction, jlist);
	spin_unlock(&transaction->t_journal->j_list_lock);
	spin_unlock(&jh->b_state_lock);
}

/*
 * Remove a buffer from its current buffer list in preparation for
 * dropping it from its current transaction entirely.  If the buffer has
 * already started to be used by a subsequent transaction, refile the
 * buffer on that transaction's metadata list.
 *
 * Called under j_list_lock
 * Called under jh->b_state_lock
 *
 * When this function returns true, there's no next transaction to refile to
 * and the caller has to drop jh reference through
 * jbd2_journal_put_journal_head().
 */
bool __jbd2_journal_refile_buffer(struct journal_head *jh)
{
	int was_dirty, jlist;
	struct buffer_head *bh = jh2bh(jh);

	lockdep_assert_held(&jh->b_state_lock);
	if (jh->b_transaction)
		assert_spin_locked(&jh->b_transaction->t_journal->j_list_lock);

	/* If the buffer is now unused, just drop it. */
	if (jh->b_next_transaction == NULL) {
		__jbd2_journal_unfile_buffer(jh);
		return true;
	}

	/*
	 * It has been modified by a later transaction: add it to the new
	 * transaction's metadata list.
	 */

	was_dirty = test_clear_buffer_jbddirty(bh);
	__jbd2_journal_temp_unlink_buffer(jh);

	/*
	 * b_transaction must be set, otherwise the new b_transaction won't
	 * be holding jh reference
	 */
	J_ASSERT_JH(jh, jh->b_transaction != NULL);

	/*
	 * We set b_transaction here because b_next_transaction will inherit
	 * our jh reference and thus __jbd2_journal_file_buffer() must not
	 * take a new one.
	 */
	WRITE_ONCE(jh->b_transaction, jh->b_next_transaction);
	WRITE_ONCE(jh->b_next_transaction, NULL);
	if (buffer_freed(bh))
		jlist = BJ_Forget;
	else if (jh->b_modified)
		jlist = BJ_Metadata;
	else
		jlist = BJ_Reserved;
	__jbd2_journal_file_buffer(jh, jh->b_transaction, jlist);
	J_ASSERT_JH(jh, jh->b_transaction->t_state == T_RUNNING);

	if (was_dirty)
		set_buffer_jbddirty(bh);
	return false;
}

/*
 * __jbd2_journal_refile_buffer() with necessary locking added. We take our
 * bh reference so that we can safely unlock bh.
 *
 * The jh and bh may be freed by this call.
 */
void jbd2_journal_refile_buffer(journal_t *journal, struct journal_head *jh)
{
	bool drop;

	spin_lock(&jh->b_state_lock);
	spin_lock(&journal->j_list_lock);
	drop = __jbd2_journal_refile_buffer(jh);
	spin_unlock(&jh->b_state_lock);
	spin_unlock(&journal->j_list_lock);
	if (drop)
		jbd2_journal_put_journal_head(jh);
}

/*
 * File inode in the inode list of the handle's transaction
 */
static int jbd2_journal_file_inode(handle_t *handle, struct jbd2_inode *jinode,
		unsigned long flags, loff_t start_byte, loff_t end_byte)
{
	transaction_t *transaction = handle->h_transaction;
	journal_t *journal;

	if (is_handle_aborted(handle))
		return -EROFS;
	journal = transaction->t_journal;

	jbd2_debug(4, "Adding inode %lu, tid:%d\n", jinode->i_vfs_inode->i_ino,
			transaction->t_tid);

	spin_lock(&journal->j_list_lock);
	jinode->i_flags |= flags;

	if (jinode->i_dirty_end) {
		jinode->i_dirty_start = min(jinode->i_dirty_start, start_byte);
		jinode->i_dirty_end = max(jinode->i_dirty_end, end_byte);
	} else {
		jinode->i_dirty_start = start_byte;
		jinode->i_dirty_end = end_byte;
	}

	/* Is inode already attached where we need it? */
	if (jinode->i_transaction == transaction ||
	    jinode->i_next_transaction == transaction)
		goto done;

	/*
	 * We only ever set this variable to 1 so the test is safe. Since
	 * t_need_data_flush is likely to be set, we do the test to save some
	 * cacheline bouncing
	 */
	if (!transaction->t_need_data_flush)
		transaction->t_need_data_flush = 1;
	/* On some different transaction's list - should be
	 * the committing one */
	if (jinode->i_transaction) {
		J_ASSERT(jinode->i_next_transaction == NULL);
		J_ASSERT(jinode->i_transaction ==
					journal->j_committing_transaction);
		jinode->i_next_transaction = transaction;
		goto done;
	}
	/* Not on any transaction list... */
	J_ASSERT(!jinode->i_next_transaction);
	jinode->i_transaction = transaction;
	list_add(&jinode->i_list, &transaction->t_inode_list);
done:
	spin_unlock(&journal->j_list_lock);

	return 0;
}

int jbd2_journal_inode_ranged_write(handle_t *handle,
		struct jbd2_inode *jinode, loff_t start_byte, loff_t length)
{
	return jbd2_journal_file_inode(handle, jinode,
			JI_WRITE_DATA | JI_WAIT_DATA, start_byte,
			start_byte + length - 1);
}

int jbd2_journal_inode_ranged_wait(handle_t *handle, struct jbd2_inode *jinode,
		loff_t start_byte, loff_t length)
{
	return jbd2_journal_file_inode(handle, jinode, JI_WAIT_DATA,
			start_byte, start_byte + length - 1);
}

/*
 * File truncate and transaction commit interact with each other in a
 * non-trivial way.  If a transaction writing data block A is
 * committing, we cannot discard the data by truncate until we have
 * written them.  Otherwise if we crashed after the transaction with
 * write has committed but before the transaction with truncate has
 * committed, we could see stale data in block A.  This function is a
 * helper to solve this problem.  It starts writeout of the truncated
 * part in case it is in the committing transaction.
 *
 * Filesystem code must call this function when inode is journaled in
 * ordered mode before truncation happens and after the inode has been
 * placed on orphan list with the new inode size. The second condition
 * avoids the race that someone writes new data and we start
 * committing the transaction after this function has been called but
 * before a transaction for truncate is started (and furthermore it
 * allows us to optimize the case where the addition to orphan list
 * happens in the same transaction as write --- we don't have to write
 * any data in such case).
 */
int jbd2_journal_begin_ordered_truncate(journal_t *journal,
					struct jbd2_inode *jinode,
					loff_t new_size)
{
	transaction_t *inode_trans, *commit_trans;
	int ret = 0;

	/* This is a quick check to avoid locking if not necessary */
	if (!jinode->i_transaction)
		goto out;
	/* Locks are here just to force reading of recent values, it is
	 * enough that the transaction was not committing before we started
	 * a transaction adding the inode to orphan list */
	read_lock(&journal->j_state_lock);
	commit_trans = journal->j_committing_transaction;
	read_unlock(&journal->j_state_lock);
	spin_lock(&journal->j_list_lock);
	inode_trans = jinode->i_transaction;
	spin_unlock(&journal->j_list_lock);
	if (inode_trans == commit_trans) {
		ret = filemap_fdatawrite_range(jinode->i_vfs_inode->i_mapping,
			new_size, LLONG_MAX);
		if (ret)
			jbd2_journal_abort(journal, ret);
	}
out:
	return ret;
}
