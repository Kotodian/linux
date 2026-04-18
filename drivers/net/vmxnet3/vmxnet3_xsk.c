// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Linux driver for VMware's vmxnet3 ethernet NIC.
 *
 * AF_XDP zero-copy data and control paths.
 *
 * Copyright (C) 2026, the vmxnet3 XSK project contributors.
 * Maintained by: pv-drivers@vmware.com
 *
 * Milestone layout (M1 -> M5):
 *   M1: scaffolding -- data-structure fields, stubs returning -EOPNOTSUPP.
 *   M2 (this revision): lifecycle for the per-qid adapter->xsk_pools[]
 *       table.  Control-path dispatcher still reports -EOPNOTSUPP on
 *       enable so a userspace ZC bind() fails cleanly, but disable
 *       requests are now idempotent no-ops to keep teardown graceful.
 *   M3: pool enable + RX zero-copy alloc/complete.
 *   M4: TX zero-copy; pool_setup starts reporting success here.
 *   M5: ndo_xsk_wakeup + need_wakeup signalling.
 *
 * Compiled unconditionally.  When CONFIG_XDP_SOCKETS is disabled the
 * bodies degenerate to trivial returns and no XSK kernel APIs are
 * touched.  Call sites can therefore invoke these entry points without
 * any ifdef of their own.
 */

#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/slab.h>

#ifdef CONFIG_XDP_SOCKETS
#include <net/xdp_sock_drv.h>
#endif

#include "vmxnet3_int.h"
#include "vmxnet3_xsk.h"

#ifdef CONFIG_XDP_SOCKETS

/*
 * Lazily allocate the per-qid xsk_pools table on first enable.
 *
 * Zero-copy users are rare enough that we do not want to pay the
 * permanent memory cost on every probed vmxnet3 netdev.  The table is
 * only ever grown at num_rx_queues and is read on hot-path wakeup, so
 * a single allocation covers the lifetime of the netdev.
 */
static int
vmxnet3_xsk_ensure_pool_table(struct vmxnet3_adapter *adapter)
{
	if (adapter->xsk_pools)
		return 0;

	adapter->xsk_pools = kcalloc(adapter->num_rx_queues,
				     sizeof(*adapter->xsk_pools),
				     GFP_KERNEL);
	if (!adapter->xsk_pools)
		return -ENOMEM;

	return 0;
}

/*
 * Disable a previously-bound umem pool on one RX queue.
 *
 * Safe to call when no pool has ever been attached: the function
 * short-circuits when the table has not been allocated or the slot is
 * NULL.  Callable from netdev unregister teardown and from userspace
 * unbind.
 */
static int
vmxnet3_xsk_pool_disable(struct vmxnet3_adapter *adapter, u16 qid)
{
	struct xsk_buff_pool *pool;

	if (qid >= adapter->num_rx_queues)
		return -EINVAL;
	if (!adapter->xsk_pools)
		return 0;

	pool = adapter->xsk_pools[qid];
	if (!pool)
		return 0;

	/* M3 will drain and tear down the queue here before unmap.  For
	 * now, no pool can have been attached because enable still
	 * returns -EOPNOTSUPP, so the unmap call below is defensive only.
	 */
	xsk_pool_dma_unmap(pool, 0);

	adapter->xsk_pools[qid] = NULL;
	adapter->rx_queue[qid].xsk_pool = NULL;
	adapter->rx_queue[qid].zc_enabled = false;
	adapter->tx_queue[qid].xsk_pool = NULL;

	return 0;
}

/*
 * Enable zero-copy on one RX queue by attaching the supplied umem pool.
 *
 * M2 returns -EOPNOTSUPP so userspace ZC bind() fails cleanly.  M3 will
 * fill in pool DMA mapping, queue rebuild, and XSK buffer handoff.
 */
static int
vmxnet3_xsk_pool_enable(struct vmxnet3_adapter *adapter,
			struct xsk_buff_pool *pool, u16 qid)
{
	int err;

	if (qid >= adapter->num_rx_queues)
		return -EINVAL;
	if (!pool)
		return -EINVAL;

	err = vmxnet3_xsk_ensure_pool_table(adapter);
	if (err)
		return err;

	if (adapter->xsk_pools[qid])
		return -EBUSY;

	/* M2: the real attach (xsk_pool_dma_map + queue rebuild) lives in
	 * M3.  Report -EOPNOTSUPP until the hot path is ready so that we
	 * never advertise a ZC capability the data path cannot honour.
	 */
	return -EOPNOTSUPP;
}

/*
 * Release the xsk_pools[] table at netdev teardown.
 *
 * Must run after every RX queue has been unbound (callers should have
 * already iterated vmxnet3_xsk_pool_disable for each qid that was
 * previously bound); this function only frees the table itself.
 */
void
vmxnet3_xsk_free_pool_table(struct vmxnet3_adapter *adapter)
{
	u32 i;

	if (!adapter->xsk_pools)
		return;

	for (i = 0; i < adapter->num_rx_queues; i++)
		vmxnet3_xsk_pool_disable(adapter, i);

	kfree(adapter->xsk_pools);
	adapter->xsk_pools = NULL;
}

int
vmxnet3_xsk_pool_setup(struct vmxnet3_adapter *adapter,
		       struct xsk_buff_pool *pool, u16 qid)
{
	if (pool)
		return vmxnet3_xsk_pool_enable(adapter, pool, qid);
	return vmxnet3_xsk_pool_disable(adapter, qid);
}

#else /* !CONFIG_XDP_SOCKETS */

void
vmxnet3_xsk_free_pool_table(struct vmxnet3_adapter *adapter)
{
}

int
vmxnet3_xsk_pool_setup(struct vmxnet3_adapter *adapter,
		       struct xsk_buff_pool *pool, u16 qid)
{
	return -EOPNOTSUPP;
}

#endif /* CONFIG_XDP_SOCKETS */

int
vmxnet3_xsk_wakeup(struct net_device *dev, u32 qid, u32 flags)
{
	/* M1 stub: wakeup never scheduled because no ZC queue is live.
	 * M5 will check adapter state, locate the target NAPI, and schedule.
	 */
	return -EOPNOTSUPP;
}

int
vmxnet3_xmit_zc(struct vmxnet3_tx_queue *tq, unsigned int budget)
{
	/* M1 stub: NAPI TX poll must be callable without effect.
	 * M4 will peek desc, fill TxDesc, and ring the doorbell.
	 */
	return 0;
}

int
vmxnet3_rq_rx_complete_zc(struct vmxnet3_rx_queue *rq,
			  struct vmxnet3_adapter *adapter, int quota)
{
	/* M1 stub: RX fast path must be callable without effect.  In M2 the
	 * control path still refuses enable, so this function stays
	 * unreachable until M3 delivers the real implementation.
	 */
	return 0;
}
