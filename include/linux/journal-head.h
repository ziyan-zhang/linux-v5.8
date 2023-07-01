/* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/linux/journal-head.h
 *
 * buffer_head fields for JBD
 *
 * 27 May 2001 Andrew Morton
 *	Created - pulled out of fs.h
 */

#ifndef JOURNAL_HEAD_H_INCLUDED
#define JOURNAL_HEAD_H_INCLUDED

#include <linux/spinlock.h>

typedef unsigned int		tid_t;		/* Unique transaction ID */
typedef struct transaction_s	transaction_t;	/* Compound transaction type */


struct buffer_head;

struct journal_head {
	/*
	 * Points back to our buffer_head. [jbd_lock_bh_journal_head()]
	 * 指回我们的buffer_head
	 */
	struct buffer_head *b_bh;

	/*
	 * Protect the buffer head state
	 * 保护buffer head状态
	 */
	spinlock_t b_state_lock;

	/*
	 * Reference count - see description in journal.c
	 * [jbd_lock_bh_journal_head()]
	 * 
	 * 引用计数-请参阅journal.c中的描述
	 */
	int b_jcount;

	/*
	 * Journalling list for this buffer [b_state_lock]
	 * NOTE: We *cannot* combine this with b_modified into a bitfield
	 * as gcc would then (which the C standard allows but which is
	 * very unuseful) make 64-bit accesses to the bitfield and clobber
	 * b_jcount if its update races with bitfield modification.
	 * 
	 * 此缓冲区的journalling列表(的buffer类型)[b_state_lock]
	 */
	unsigned b_jlist;

	/*
	 * This flag signals the buffer has been modified by
	 * the currently running transaction
	 * [b_state_lock]
	 * 
	 * 此标志表示缓冲区已由当前running transaction修改
	 */
	unsigned b_modified;

	/*
	 * Copy of the buffer data frozen for writing to the log.
	 * [b_state_lock]
	 * 
	 * 冻结的缓冲区数据的副本，用于写入日志
	 * [b_state_lock]
	 */
	char *b_frozen_data;

	/*
	 * Pointer to a saved copy of the buffer containing no uncommitted
	 * deallocation references, so that allocations can avoid overwriting
	 * uncommitted deletes. [b_state_lock]
	 * 
	 * 指向缓冲区保存的副本，该副本不包含未提交的 *取消分配引用（deallocation references）*，
	 * 因此分配可以避免覆盖未提交的删除。
	 */
	char *b_committed_data;

	/*
	 * Pointer to the compound transaction which owns this buffer's
	 * metadata: either the running transaction or the committing
	 * transaction (if there is one).  Only applies to buffers on a
	 * transaction's data or metadata journaling list.
	 * [j_list_lock] [b_state_lock]
	 * Either of these locks is enough for reading, both are needed for
	 * changes.
	 * 
	 * 指向拥有此缓冲区元数据的复合事务的指针：正在运行的事务或提交事务（如果有）。
	 * 仅适用于事务数据或元数据 journaling 列表上的缓冲区。
	 */
	transaction_t *b_transaction;

	/*
	 * Pointer to the running compound transaction which is currently
	 * modifying the buffer's metadata, if there was already a transaction
	 * committing it when the new transaction touched it.
	 * [t_list_lock] [b_state_lock]
	 * 
	 * 指向当前正在修改缓冲区元数据的running复合事物的指针，
	 * 如果新事物touch它时已经有一个事务提交它
	 */
	transaction_t *b_next_transaction;

	/*
	 * Doubly-linked list of buffers on a transaction's data, metadata or
	 * forget queue. [t_list_lock] [b_state_lock]
	 * 
	 * 事务数据，元数据或忘记队列上的缓冲区的双向链表
	 */
	struct journal_head *b_tnext, *b_tprev;

	/*
	 * Pointer to the compound transaction against which this buffer
	 * is checkpointed.  Only dirty buffers can be checkpointed.
	 * [j_list_lock]
	 * 
	 * 指向为此缓冲区检查点的复合事务的指针。只有脏缓冲区才能被检查点
	 */
	transaction_t *b_cp_transaction;

	/*
	 * Doubly-linked list of buffers still remaining to be flushed
	 * before an old transaction can be checkpointed.
	 * [j_list_lock]
	 * 
	 * 在旧事务可以被检查点之前，仍然需要刷新的缓冲区的双向链表.
	 */
	// TODO: WHAT?
	struct journal_head *b_cpnext, *b_cpprev;

	/* Trigger type */
	struct jbd2_buffer_trigger_type *b_triggers;

	/* Trigger type for the committing transaction's frozen data */
	struct jbd2_buffer_trigger_type *b_frozen_triggers;
};

#endif		/* JOURNAL_HEAD_H_INCLUDED */
