// SPDX-License-Identifier: GPL-2.0+
/*
 * linux/fs/jbd2/checkpoint.c
 *
 * Written by Stephen C. Tweedie <sct@redhat.com>, 1999
 *
 * Copyright 1999 Red Hat Software --- All Rights Reserved
 *
 * Checkpoint routines for the generic filesystem journaling code.
 * Part of the ext2fs journaling system.
 *
 * Checkpointing is the process of ensuring that a section of the log is
 * committed fully to disk, so that that portion of the log can be
 * reused.
 */

#include <linux/time.h>
#include <linux/fs.h>
#include <linux/jbd2.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <trace/events/jbd2.h>

/*
 * Unlink a buffer from a transaction checkpoint list.
 *
 * Called with j_list_lock held.
 */
static inline void __buffer_unlink_first(struct journal_head *jh)
{
	transaction_t *transaction = jh->b_cp_transaction;

	jh->b_cpnext->b_cpprev = jh->b_cpprev;
	jh->b_cpprev->b_cpnext = jh->b_cpnext;
	if (transaction->t_checkpoint_list == jh) {
		transaction->t_checkpoint_list = jh->b_cpnext;
		if (transaction->t_checkpoint_list == jh)
			transaction->t_checkpoint_list = NULL;
	}
}

/*
 * Unlink a buffer from a transaction checkpoint(io) list.
 *
 * Called with j_list_lock held.
 */
static inline void __buffer_unlink(struct journal_head *jh)
{
	transaction_t *transaction = jh->b_cp_transaction;

	__buffer_unlink_first(jh);
	if (transaction->t_checkpoint_io_list == jh) {
		transaction->t_checkpoint_io_list = jh->b_cpnext;
		if (transaction->t_checkpoint_io_list == jh)
			transaction->t_checkpoint_io_list = NULL;
	}
}

// todo: 为什么要区分buffer list和buffer io list呢？
/*
 * Move a buffer from the checkpoint list to the checkpoint io list
 *
 * Called with j_list_lock held
 */
static inline void __buffer_relink_io(struct journal_head *jh)
{
	transaction_t *transaction = jh->b_cp_transaction;	// 指向为此缓冲区设置的复合事务的指针

	__buffer_unlink_first(jh);

	if (!transaction->t_checkpoint_io_list) {
		jh->b_cpnext = jh->b_cpprev = jh;	// 没尊别的需要刷新的缓冲区，就当前jh自己闭环了
	} else {
		// jh->b_cpnext, jh->b_cpprev：在旧事务可以被检查点之前，仍然需要刷新的缓冲区的双向链表
		jh->b_cpnext = transaction->t_checkpoint_io_list;
		jh->b_cpprev = transaction->t_checkpoint_io_list->b_cpprev;
		jh->b_cpprev->b_cpnext = jh;
		jh->b_cpnext->b_cpprev = jh;
	}
	transaction->t_checkpoint_io_list = jh;
}

/*
 * Check a checkpoint buffer could be release or not.
 *
 * Requires j_list_lock
 */
static inline bool __cp_buffer_busy(struct journal_head *jh)
{
	struct buffer_head *bh = jh2bh(jh);

	// jh->b_transaction: 指向拥有此缓冲区元数据的复合事务的指针
	return (jh->b_transaction || buffer_locked(bh) || buffer_dirty(bh));
}

/*
 * __jbd2_log_wait_for_space: wait until there is space in the journal.
 *
 * Called under j-state_lock *only*.  It will be unlocked if we have to wait
 * for a checkpoint to free up some space in the log.
 */
void __jbd2_log_wait_for_space(journal_t *journal)
__acquires(&journal->j_state_lock)
__releases(&journal->j_state_lock)
{
	int nblocks, space_left;
	/* assert_spin_locked(&journal->j_state_lock); */

	nblocks = journal->j_max_transaction_buffers;
	while (jbd2_log_space_left(journal) < nblocks) {
		write_unlock(&journal->j_state_lock);	// jouranl剩余空间太小，导致当前线程写不了了，先放开锁，让别的线程写
		mutex_lock_io(&journal->j_checkpoint_mutex);	// 获取checkpoint互斥锁

		/*
		 * Test again, another process may have checkpointed while we
		 * were waiting for the checkpoint lock. If there are no
		 * transactions ready to be checkpointed, try to recover
		 * journal space by calling cleanup_journal_tail(), and if
		 * that doesn't work, by waiting for the currently committing
		 * transaction to complete.  If there is absolutely no way
		 * to make progress, this is either a BUG or corrupted
		 * filesystem, so abort the journal and leave a stack
		 * trace for forensic evidence.
		 */
		write_lock(&journal->j_state_lock);
		if (journal->j_flags & JBD2_ABORT) {
			mutex_unlock(&journal->j_checkpoint_mutex);
			return;
		}
		spin_lock(&journal->j_list_lock);	// journal->j_list_lock: 保护buffer列表和内部buffer状态
		space_left = jbd2_log_space_left(journal);
		if (space_left < nblocks) {
			int chkpt = journal->j_checkpoint_transactions != NULL;
			tid_t tid = 0;

			if (journal->j_committing_transaction)
				tid = journal->j_committing_transaction->t_tid;
			spin_unlock(&journal->j_list_lock);
			write_unlock(&journal->j_state_lock);
			if (chkpt) {
				jbd2_log_do_checkpoint(journal);
			} else if (jbd2_cleanup_journal_tail(journal) == 0) {
				/* We were able to recover space; yay! */
				;
			} else if (tid) {
				/*
				 * jbd2_journal_commit_transaction() may want
				 * to take the checkpoint_mutex if JBD2_FLUSHED
				 * is set.  So we need to temporarily drop it.
				 */
				mutex_unlock(&journal->j_checkpoint_mutex);
				jbd2_log_wait_commit(journal, tid);
				write_lock(&journal->j_state_lock);
				continue;
			} else {
				printk(KERN_ERR "%s: needed %d blocks and "
				       "only had %d space available\n",
				       __func__, nblocks, space_left);
				printk(KERN_ERR "%s: no way to get more "
				       "journal space in %s\n", __func__,
				       journal->j_devname);
				WARN_ON(1);
				jbd2_journal_abort(journal, -EIO);
			}
			write_lock(&journal->j_state_lock);
		} else {
			spin_unlock(&journal->j_list_lock);
		}
		mutex_unlock(&journal->j_checkpoint_mutex);
	}
}

static void
__flush_batch(journal_t *journal, int *batch_count)
{
	int i;
	struct blk_plug plug;	// blk_plug的作用是将IO请求缓存在队列中以提高IO操作的效率

	blk_start_plug(&plug);
	for (i = 0; i < *batch_count; i++)
		write_dirty_buffer(journal->j_chkpt_bhs[i], REQ_SYNC);
	blk_finish_plug(&plug);

	for (i = 0; i < *batch_count; i++) {
		struct buffer_head *bh = journal->j_chkpt_bhs[i];
		BUFFER_TRACE(bh, "brelse");
		__brelse(bh);
	}
	*batch_count = 0;
}

/*
 * Perform an actual checkpoint. We take the first transaction on the
 * list of transactions to be checkpointed and send all its buffers
 * to disk. We submit larger chunks of data at once.
 *
 * The journal should be locked before calling this function.
 * Called with j_checkpoint_mutex held.
 * 
 * 执行一个实际的checkpoint。我们获取要被ckeckpointed的事务列表中的第一个事务，
 * 将其所有的缓冲区发送到磁盘。我们一次提交更大的数据块。
 * 
 * 在调用此函数之前，应该锁定日志。在持有j_checkpoint_mutex的情况下调用。
 */
int jbd2_log_do_checkpoint(journal_t *journal)
{
	struct journal_head	*jh;
	struct buffer_head	*bh;
	transaction_t		*transaction;
	tid_t			this_tid;
	int			result, batch_count = 0;

	jbd2_debug(1, "Start checkpoint\n");

	/*
	 * First thing: if there are any transactions in the log which
	 * don't need checkpointing, just eliminate them from the
	 * journal straight away.
	 */
	result = jbd2_cleanup_journal_tail(journal);
	trace_jbd2_checkpoint(journal, result);
	jbd2_debug(1, "cleanup_journal_tail returned %d\n", result);
	if (result <= 0)
		return result;

	/*
	 * OK, we need to start writing disk blocks.  Take one transaction
	 * and write it.
	 */
	spin_lock(&journal->j_list_lock);
	if (!journal->j_checkpoint_transactions)
		goto out;
	transaction = journal->j_checkpoint_transactions;
	if (transaction->t_chp_stats.cs_chp_time == 0)
		transaction->t_chp_stats.cs_chp_time = jiffies;
	this_tid = transaction->t_tid;
restart:
	/*
	 * If someone cleaned up this transaction while we slept, we're
	 * done (maybe it's a new transaction, but it fell at the same
	 * address).
	 */
	if (journal->j_checkpoint_transactions != transaction ||
	    transaction->t_tid != this_tid)
		goto out;

	/* checkpoint all of the transaction's buffers */
	while (transaction->t_checkpoint_list) {
		jh = transaction->t_checkpoint_list;
		bh = jh2bh(jh);

		if (buffer_locked(bh)) {
			get_bh(bh);
			spin_unlock(&journal->j_list_lock);
			wait_on_buffer(bh);
			/* the journal_head may have gone by now */
			BUFFER_TRACE(bh, "brelse");
			__brelse(bh);
			goto retry;
		}
		if (jh->b_transaction != NULL) {
			transaction_t *t = jh->b_transaction;
			tid_t tid = t->t_tid;

			transaction->t_chp_stats.cs_forced_to_close++;
			spin_unlock(&journal->j_list_lock);
			if (unlikely(journal->j_flags & JBD2_UNMOUNT))
				/*
				 * The journal thread is dead; so
				 * starting and waiting for a commit
				 * to finish will cause us to wait for
				 * a _very_ long time.
				 */
				printk(KERN_ERR
		"JBD2: %s: Waiting for Godot: block %llu\n",
		journal->j_devname, (unsigned long long) bh->b_blocknr);

			if (batch_count)
				__flush_batch(journal, &batch_count);
			jbd2_log_start_commit(journal, tid);
			/*
			 * jbd2_journal_commit_transaction() may want
			 * to take the checkpoint_mutex if JBD2_FLUSHED
			 * is set, jbd2_update_log_tail() called by
			 * jbd2_journal_commit_transaction() may also take
			 * checkpoint_mutex.  So we need to temporarily
			 * drop it.
			 */
			mutex_unlock(&journal->j_checkpoint_mutex);
			jbd2_log_wait_commit(journal, tid);
			mutex_lock_io(&journal->j_checkpoint_mutex);
			spin_lock(&journal->j_list_lock);
			goto restart;
		}
		if (!buffer_dirty(bh)) {
			BUFFER_TRACE(bh, "remove from checkpoint");
			if (__jbd2_journal_remove_checkpoint(jh))
				/* The transaction was released; we're done */
				goto out;
			continue;
		}
		/*
		 * Important: we are about to write the buffer, and
		 * possibly block, while still holding the journal
		 * lock.  We cannot afford to let the transaction
		 * logic start messing around with this buffer before
		 * we write it to disk, as that would break
		 * recoverability.
		 */
		BUFFER_TRACE(bh, "queue");
		get_bh(bh);
		J_ASSERT_BH(bh, !buffer_jwrite(bh));
		journal->j_chkpt_bhs[batch_count++] = bh;
		__buffer_relink_io(jh);
		transaction->t_chp_stats.cs_written++;
		if ((batch_count == JBD2_NR_BATCH) ||
		    need_resched() ||
		    spin_needbreak(&journal->j_list_lock))
			goto unlock_and_flush;
	}

	if (batch_count) {
		unlock_and_flush:
			spin_unlock(&journal->j_list_lock);
		retry:
			if (batch_count)
				__flush_batch(journal, &batch_count);
			spin_lock(&journal->j_list_lock);
			goto restart;
	}

	/*
	 * Now we issued all of the transaction's buffers, let's deal
	 * with the buffers that are out for I/O.
	 */
restart2:
	/* Did somebody clean up the transaction in the meanwhile? */
	if (journal->j_checkpoint_transactions != transaction ||
	    transaction->t_tid != this_tid)
		goto out;

	while (transaction->t_checkpoint_io_list) {
		jh = transaction->t_checkpoint_io_list;
		bh = jh2bh(jh);
		if (buffer_locked(bh)) {
			get_bh(bh);
			spin_unlock(&journal->j_list_lock);
			wait_on_buffer(bh);
			/* the journal_head may have gone by now */
			BUFFER_TRACE(bh, "brelse");
			__brelse(bh);
			spin_lock(&journal->j_list_lock);
			goto restart2;
		}

		/*
		 * Now in whatever state the buffer currently is, we
		 * know that it has been written out and so we can
		 * drop it from the list
		 */
		if (__jbd2_journal_remove_checkpoint(jh))
			break;
	}
out:
	spin_unlock(&journal->j_list_lock);
	result = jbd2_cleanup_journal_tail(journal);

	return (result < 0) ? result : 0;
}

/*
 * Check the list of checkpoint transactions for the journal to see if
 * we have already got rid of any since the last update of the log tail
 * in the journal superblock.  If so, we can instantly roll the
 * superblock forward to remove those transactions from the log.
 *
 * Return <0 on error, 0 on success, 1 if there was nothing to clean up.
 *
 * Called with the journal lock held.
 *
 * This is the only part of the journaling code which really needs to be
 * aware of transaction aborts.  Checkpointing involves writing to the
 * main filesystem area rather than to the journal, so it can proceed
 * even in abort state, but we must not update the super block if
 * checkpointing may have failed.  Otherwise, we would lose some metadata
 * buffers which should be written-back to the filesystem.
 * 
 * 检查日志的检查点事务列表，看看自上次更新超级块中的日志尾部以来，我们是否已经删除了任何事务。
 * 如果是，我们可以立即前滚超级块以从日志中删除这些事务。
 * 
 * 返回<0表示错误，0表示成功，1表示没有要清理的内容。
 * 
 * 这是唯一需要注意事务终止的日志代码部分。检查点涉及写入主文件系统区域而不是日志，因此即使在中止状态下也可以继续进行，
 * 但是如果检查点可能失败，则不能更新超级块。否则，我们将丢失应写回文件系统的某些元数据缓冲区。
 */

int jbd2_cleanup_journal_tail(journal_t *journal)
{
	tid_t		first_tid;
	unsigned long	blocknr;

	if (is_journal_aborted(journal))	// 事务终止，返回负数表示错误
		return -EIO;

	if (!jbd2_journal_get_log_tail(journal, &first_tid, &blocknr))	// 返回1
		return 1;
	J_ASSERT(blocknr != 0);

	/*
	 * We need to make sure that any blocks that were recently written out
	 * --- perhaps by jbd2_log_do_checkpoint() --- are flushed out before
	 * we drop the transactions from the journal. It's unlikely this will
	 * be necessary, especially with an appropriately sized journal, but we
	 * need this to guarantee correctness.  Fortunately
	 * jbd2_cleanup_journal_tail() doesn't get called all that often.
	 */
	if (journal->j_flags & JBD2_BARRIER)
		blkdev_issue_flush(journal->j_fs_dev);

	return __jbd2_update_log_tail(journal, first_tid, blocknr);
}


/* Checkpoint list management */

/*
 * journal_clean_one_cp_list
 *
 * Find all the written-back checkpoint buffers in the given list and
 * release them. If 'destroy' is set, clean all buffers unconditionally.
 *
 * Called with j_list_lock held.
 * Returns 1 if we freed the transaction, 0 otherwise.
 */
static int journal_clean_one_cp_list(struct journal_head *jh, bool destroy)
{
	struct journal_head *last_jh;
	struct journal_head *next_jh = jh;

	if (!jh)
		return 0;

	last_jh = jh->b_cpprev;
	do {
		jh = next_jh;
		next_jh = jh->b_cpnext;

		if (!destroy && __cp_buffer_busy(jh))
			return 0;

		if (__jbd2_journal_remove_checkpoint(jh))
			return 1;
		/*
		 * This function only frees up some memory
		 * if possible so we dont have an obligation
		 * to finish processing. Bail out if preemption
		 * requested:
		 * 
		 * 此函数仅在可能的情况下释放一些内存，因此我们没有义务完成处理。
		 * 如果请求了抢占，则退出：
		 */
		if (need_resched())
			return 0;
	} while (jh != last_jh);

	return 0;
}

/*
 * journal_shrink_one_cp_list
 *
 * Find 'nr_to_scan' written-back checkpoint buffers in the given list
 * and try to release them. If the whole transaction is released, set
 * the 'released' parameter. Return the number of released checkpointed
 * buffers.
 * 
 * 在给定列表中找到 nr_to_scan 个写回（written-back）检查点缓冲区，并尝试释放它们。
 * 如果整个事务被释放，则设置'released'参数。返回已释放的检查点缓冲区数。
 *
 * Called with j_list_lock held.
 */
static unsigned long journal_shrink_one_cp_list(struct journal_head *jh,
						unsigned long *nr_to_scan,
						bool *released)
{
	struct journal_head *last_jh;
	struct journal_head *next_jh = jh;
	unsigned long nr_freed = 0;
	int ret;

	if (!jh || *nr_to_scan == 0)
		return 0;

	last_jh = jh->b_cpprev;
	do {
		jh = next_jh;
		next_jh = jh->b_cpnext;

		(*nr_to_scan)--;
		if (__cp_buffer_busy(jh))
			continue;

		nr_freed++;
		ret = __jbd2_journal_remove_checkpoint(jh);
		if (ret) {
			*released = true;
			break;
		}

		if (need_resched())
			break;
	} while (jh != last_jh && *nr_to_scan);

	return nr_freed;
}

/*
 * jbd2_journal_shrink_checkpoint_list
 *
 * Find 'nr_to_scan' written-back checkpoint buffers in the journal
 * and try to release them. Return the number of released checkpointed
 * buffers.
 *
 * Called with j_list_lock held.
 * 
 * 找到日志中的 nr_to_scan 个写回检查点缓冲区，并尝试释放它们。返回已释放的检查点缓冲区数。
 * 调用的时候持有 j_list_lock 锁。
 */
unsigned long jbd2_journal_shrink_checkpoint_list(journal_t *journal,
						  unsigned long *nr_to_scan)
{
	transaction_t *transaction, *last_transaction, *next_transaction;
	bool released;
	tid_t first_tid = 0, last_tid = 0, next_tid = 0;
	tid_t tid = 0;
	unsigned long nr_freed = 0;
	unsigned long nr_scanned = *nr_to_scan;

again:
	spin_lock(&journal->j_list_lock);
	if (!journal->j_checkpoint_transactions) {
		spin_unlock(&journal->j_list_lock);
		goto out;
	}

	/*
	 * Get next shrink transaction, resume previous scan or start
	 * over again. If some others do checkpoint and drop transaction
	 * from the checkpoint list, we ignore saved j_shrink_transaction
	 * and start over unconditionally.
	 */
	if (journal->j_shrink_transaction)
		transaction = journal->j_shrink_transaction;
	else
		transaction = journal->j_checkpoint_transactions;

	if (!first_tid)
		first_tid = transaction->t_tid;
	last_transaction = journal->j_checkpoint_transactions->t_cpprev;
	next_transaction = transaction;
	last_tid = last_transaction->t_tid;
	do {
		transaction = next_transaction;
		next_transaction = transaction->t_cpnext;
		tid = transaction->t_tid;
		released = false;

		nr_freed += journal_shrink_one_cp_list(transaction->t_checkpoint_list,
						       nr_to_scan, &released);
		if (*nr_to_scan == 0)
			break;
		if (need_resched() || spin_needbreak(&journal->j_list_lock))
			break;
		if (released)
			continue;

		nr_freed += journal_shrink_one_cp_list(transaction->t_checkpoint_io_list,
						       nr_to_scan, &released);
		if (*nr_to_scan == 0)
			break;
		if (need_resched() || spin_needbreak(&journal->j_list_lock))
			break;
	} while (transaction != last_transaction);

	if (transaction != last_transaction) {
		journal->j_shrink_transaction = next_transaction;
		next_tid = next_transaction->t_tid;
	} else {
		journal->j_shrink_transaction = NULL;
		next_tid = 0;
	}

	spin_unlock(&journal->j_list_lock);
	cond_resched();

	if (*nr_to_scan && next_tid)
		goto again;
out:
	nr_scanned -= *nr_to_scan;
	trace_jbd2_shrink_checkpoint_list(journal, first_tid, tid, last_tid,
					  nr_freed, nr_scanned, next_tid);

	return nr_freed;
}

/*
 * journal_clean_checkpoint_list
 *
 * Find all the written-back checkpoint buffers in the journal and release them.
 * If 'destroy' is set, release all buffers unconditionally.
 *
 * Called with j_list_lock held.
 */
void __jbd2_journal_clean_checkpoint_list(journal_t *journal, bool destroy)
{
	transaction_t *transaction, *last_transaction, *next_transaction;
	int ret;

	transaction = journal->j_checkpoint_transactions;
	if (!transaction)
		return;

	last_transaction = transaction->t_cpprev;
	next_transaction = transaction;
	do {
		transaction = next_transaction;
		next_transaction = transaction->t_cpnext;
		ret = journal_clean_one_cp_list(transaction->t_checkpoint_list,
						destroy);
		/*
		 * This function only frees up some memory if possible so we
		 * dont have an obligation to finish processing. Bail out if
		 * preemption requested:
		 */
		if (need_resched())
			return;
		if (ret)
			continue;
		/*
		 * It is essential that we are as careful as in the case of
		 * t_checkpoint_list with removing the buffer from the list as
		 * we can possibly see not yet submitted buffers on io_list
		 */
		ret = journal_clean_one_cp_list(transaction->
				t_checkpoint_io_list, destroy);
		if (need_resched())
			return;
		/*
		 * Stop scanning if we couldn't free the transaction. This
		 * avoids pointless scanning of transactions which still
		 * weren't checkpointed.
		 */
		if (!ret)
			return;
	} while (transaction != last_transaction);
}

/*
 * Remove buffers from all checkpoint lists as journal is aborted and we just
 * need to free memory
 */
void jbd2_journal_destroy_checkpoint(journal_t *journal)
{
	/*
	 * We loop because __jbd2_journal_clean_checkpoint_list() may abort
	 * early due to a need of rescheduling.
	 */
	while (1) {
		spin_lock(&journal->j_list_lock);
		if (!journal->j_checkpoint_transactions) {
			spin_unlock(&journal->j_list_lock);
			break;
		}
		__jbd2_journal_clean_checkpoint_list(journal, true);
		spin_unlock(&journal->j_list_lock);
		cond_resched();
	}
}

/*
 * journal_remove_checkpoint: called after a buffer has been committed
 * to disk (either by being write-back flushed to disk, or being
 * committed to the log).
 * 
 * 在缓冲区已提交到磁盘（通过write-back刷新到磁盘，或者提交到日志）之后调用
 *
 * We cannot safely clean a transaction out of the log until all of the
 * buffer updates committed in that transaction have safely been stored
 * elsewhere on disk.  To achieve this, all of the buffers in a
 * transaction need to be maintained on the transaction's checkpoint
 * lists until they have been rewritten, at which point this function is
 * called to remove the buffer from the existing transaction's
 * checkpoint lists.
 *
 * 直到提交到该事务中的所有缓冲区更新都已安全地存储在磁盘的其他位置之后，我们才能安全地
 * 清除日志中的事务。为了做到这点，事务中的所有缓冲区，都需要维护在事务的检查点列表中，
 * 直到它们被重写，此时该函数被调用，从现有事务的检查点列表中删除缓冲区。
 * 
 * The function returns 1 if it frees the transaction, 0 otherwise.
 * The function can free jh and bh.
 * 
 * 如果函数释放了事务，则返回1，否则返回0。函数可以释放jh和bh。
 *
 * This function is called with j_list_lock held.
 */
int __jbd2_journal_remove_checkpoint(struct journal_head *jh)
{
	struct transaction_chp_stats_s *stats;
	transaction_t *transaction;
	journal_t *journal;
	struct buffer_head *bh = jh2bh(jh);

	JBUFFER_TRACE(jh, "entry");

	transaction = jh->b_cp_transaction;
	if (!transaction) {
		JBUFFER_TRACE(jh, "not on transaction");
		return 0;
	}
	journal = transaction->t_journal;

	JBUFFER_TRACE(jh, "removing from transaction");

	/*
	 * If we have failed to write the buffer out to disk, the filesystem
	 * may become inconsistent. We cannot abort the journal here since
	 * we hold j_list_lock and we have to be careful about races with
	 * jbd2_journal_destroy(). So mark the writeback IO error in the
	 * journal here and we abort the journal later from a better context.
	 * 
	 * 如果我们未能将缓冲区写出到磁盘，文件系统可能会变得不一致。我们不能在这里中止日志，
	 * 因为我们持有 j_list_lock 并且我们必须小心与 jbd2_journal_destroy() 的竞争。
	 * 因此，在这里在日志中标记写回IO错误，稍后我们从更好的上下文中中止日志。
	 */
	if (buffer_write_io_error(bh))
		set_bit(JBD2_CHECKPOINT_IO_ERROR, &journal->j_atomic_flags);

	__buffer_unlink(jh);
	jh->b_cp_transaction = NULL;
	percpu_counter_dec(&journal->j_checkpoint_jh_count);
	jbd2_journal_put_journal_head(jh);

	/* Is this transaction empty? */
	if (transaction->t_checkpoint_list || transaction->t_checkpoint_io_list)
		return 0;

	/*
	 * There is one special case to worry about: if we have just pulled the
	 * buffer off a running or committing transaction's checkpoing list,
	 * then even if the checkpoint list is empty, the transaction obviously
	 * cannot be dropped!
	 * 
	 * 有一个特殊情况需要担心：如果我们刚刚从运行或提交事务的检查点列表中删除了缓冲区，
	 * 那么即使检查点列表为空，该事务显然也不能被删除！
	 *
	 * The locking here around t_state is a bit sleazy.
	 * See the comment at the end of jbd2_journal_commit_transaction().
	 */
	if (transaction->t_state != T_FINISHED)
		return 0;

	/*
	 * OK, that was the last buffer for the transaction, we can now
	 * safely remove this transaction from the log.
	 */
	stats = &transaction->t_chp_stats;
	if (stats->cs_chp_time)
		stats->cs_chp_time = jbd2_time_diff(stats->cs_chp_time,
						    jiffies);
	trace_jbd2_checkpoint_stats(journal->j_fs_dev->bd_dev,
				    transaction->t_tid, stats);

	__jbd2_journal_drop_transaction(journal, transaction);
	jbd2_journal_free_transaction(transaction);
	return 1;
}

/*
 * journal_insert_checkpoint: put a committed buffer onto a checkpoint
 * list so that we know when it is safe to clean the transaction out of
 * the log.
 * 
 * journal_insert_checkpoint: 将已提交的缓冲区 jh 放入 事务transaction 的检查点列表，
 * 以便我们知道何时可以安全地清除日志中的事务（那肯定是checkpoint完了才能清除日志区的事务）。
 *
 * Called with the journal locked.
 * Called with j_list_lock held.
 */
void __jbd2_journal_insert_checkpoint(struct journal_head *jh,
			       transaction_t *transaction)
{
	JBUFFER_TRACE(jh, "entry");
	J_ASSERT_JH(jh, buffer_dirty(jh2bh(jh)) || buffer_jbddirty(jh2bh(jh)));
	J_ASSERT_JH(jh, jh->b_cp_transaction == NULL);

	/* Get reference for checkpointing transaction */
	jbd2_journal_grab_journal_head(jh2bh(jh));
	jh->b_cp_transaction = transaction;

	if (!transaction->t_checkpoint_list) {
		jh->b_cpnext = jh->b_cpprev = jh;	// transaction里面没有ckpt_list，jh自己闭环
	} else {	// 将 jh 插入到 transaction 的检查点列表中
		jh->b_cpnext = transaction->t_checkpoint_list;
		jh->b_cpprev = transaction->t_checkpoint_list->b_cpprev;
		jh->b_cpprev->b_cpnext = jh;
		jh->b_cpnext->b_cpprev = jh;
	}
	transaction->t_checkpoint_list = jh;	// jh成为新的 t_checkpoint_list 列表头
	percpu_counter_inc(&transaction->t_journal->j_checkpoint_jh_count);
}

/*
 * We've finished with this transaction structure: adios...
 *
 * The transaction must have no links except for the checkpoint by this
 * point.
 * 
 * 我们已经完成了这个事务结构：再见...
 * 在这个点，此事务必须没有除检查点之外的链接。
 *
 * Called with the journal locked.
 * Called with j_list_lock held.
 */

void __jbd2_journal_drop_transaction(journal_t *journal, transaction_t *transaction)
{
	assert_spin_locked(&journal->j_list_lock);

	journal->j_shrink_transaction = NULL;
	if (transaction->t_cpnext) {	// 将当前transaction从（checkpoint_）transactions链表中移除
		transaction->t_cpnext->t_cpprev = transaction->t_cpprev;
		transaction->t_cpprev->t_cpnext = transaction->t_cpnext;
		// journal中的j_checkpoint_transactions指向函数参数中给的transaction，且该参数transaction是他自己
		// 那就是全部checkpoint_transaction都完成了，所以j_checkpoint_transactions指向NULL
		if (journal->j_checkpoint_transactions == transaction)
			journal->j_checkpoint_transactions =
				transaction->t_cpnext;
		if (journal->j_checkpoint_transactions == transaction)
			journal->j_checkpoint_transactions = NULL;
	}

	J_ASSERT(transaction->t_state == T_FINISHED);
	J_ASSERT(transaction->t_buffers == NULL);
	J_ASSERT(transaction->t_forget == NULL);
	J_ASSERT(transaction->t_shadow_list == NULL);
	J_ASSERT(transaction->t_checkpoint_list == NULL);
	J_ASSERT(transaction->t_checkpoint_io_list == NULL);
	J_ASSERT(atomic_read(&transaction->t_updates) == 0);
	J_ASSERT(journal->j_committing_transaction != transaction);
	J_ASSERT(journal->j_running_transaction != transaction);

	trace_jbd2_drop_transaction(journal, transaction);

	jbd2_debug(1, "Dropping transaction %d, all done\n", transaction->t_tid);
}
