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
 *   M1: scaffolding -- data-structure fields and -EOPNOTSUPP stubs.
 *   M2: per-qid xsk_pools[] lifecycle; pool_setup still rejects enable.
 *   M3 (this revision): real pool enable/disable (DMA map + queue
 *       rebuild), RX zero-copy alloc / complete / cleanup.  pool_setup
 *       returns 0 on success so userspace `xdpsock -r -z` starts
 *       receiving.  TX still reports no work; users attempting
 *       `xdpsock -t -z`/`-l -z` will see TX stall until M4.
 *   M4: TX zero-copy.
 *   M5: ndo_xsk_wakeup + need_wakeup signalling.
 *
 * Compiled unconditionally.  When CONFIG_XDP_SOCKETS is disabled the
 * bodies degenerate to trivial returns and no XSK kernel APIs are
 * touched, so callers can invoke these entry points without their own
 * ifdef.
 */

#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/slab.h>

#ifdef CONFIG_XDP_SOCKETS
#include <linux/bpf_trace.h>
#include <net/xdp_sock_drv.h>
#endif

#include "vmxnet3_int.h"
#include "vmxnet3_xsk.h"

#ifdef CONFIG_XDP_SOCKETS

#define VMXNET3_XSK_ALLOC_BATCH	64

static int vmxnet3_xsk_pool_disable(struct vmxnet3_adapter *adapter, u16 qid);

/*
 * Lazily allocate the per-qid xsk_pools table on first enable.
 *
 * Zero-copy users are rare enough that we do not want to pay the
 * permanent memory cost on every probed vmxnet3 netdev.  The table is
 * only ever grown to num_rx_queues and is read on hot-path wakeup, so
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
 * Fast-path RX refill from the bound XSK pool.  Fills rx_ring[0] (the
 * "head" ring) with umem chunks; v1 does not put XSK buffers on
 * rx_ring[1] because multi-buffer scatter is not yet wired up -- see
 * vmxnet3_rq_init_xsk() which keeps ring[1] empty.
 *
 * Returns number of descriptors filled.  A short return (possibly 0)
 * means the umem FILL ring is drained; caller is expected to re-try on
 * the next NAPI tick after userspace replenishes it.
 */
int
vmxnet3_rq_alloc_rx_buf_xsk(struct vmxnet3_rx_queue *rq, int num_to_alloc)
{
	struct vmxnet3_cmd_ring *ring = &rq->rx_ring[0];
	struct vmxnet3_rx_buf_info *rbi_base = rq->buf_info[0];
	struct xdp_buff *xdp_batch[VMXNET3_XSK_ALLOC_BATCH];
	int allocated = 0;
	u32 frame_len;

	if (unlikely(!rq->xsk_pool))
		return 0;

	frame_len = xsk_pool_get_rx_frame_size(rq->xsk_pool);

	while (allocated < num_to_alloc) {
		u32 batch, got, i;

		batch = min_t(u32, num_to_alloc - allocated,
			      ARRAY_SIZE(xdp_batch));
		got = xsk_buff_alloc_batch(rq->xsk_pool, xdp_batch, batch);
		if (!got)
			break;

		for (i = 0; i < got; i++) {
			struct vmxnet3_rx_buf_info *rbi;
			union Vmxnet3_GenericDesc *gd;
			u32 val;

			rbi = rbi_base + ring->next2fill;
			gd = ring->base + ring->next2fill;

			rbi->buf_type = VMXNET3_RX_BUF_XSK;
			rbi->xsk_xdp = xdp_batch[i];
			rbi->dma_addr = xsk_buff_xdp_get_dma(xdp_batch[i]);
			rbi->len = frame_len;
			rbi->comp_state = VMXNET3_RXD_COMP_PENDING;

			gd->rxd.addr = cpu_to_le64(rbi->dma_addr);
			val = VMXNET3_RXD_BTYPE_HEAD << VMXNET3_RXD_BTYPE_SHIFT;
			gd->dword[2] = cpu_to_le32(
				(!ring->gen << VMXNET3_RXD_GEN_SHIFT) |
				val | rbi->len);

			/* Hold the last descriptor back from the device so the
			 * ring cannot be mistaken for full vs. empty.  The
			 * common path below will mark it ready only once the
			 * next refill adds a slot after it.
			 */
			if (allocated + i + 1 == num_to_alloc) {
				rbi->comp_state = VMXNET3_RXD_COMP_DONE;
				allocated += i + 1;
				goto out;
			}

			gd->dword[2] |= cpu_to_le32(ring->gen <<
						    VMXNET3_RXD_GEN_SHIFT);
			vmxnet3_cmd_ring_adv_next2fill(ring);
		}

		allocated += got;
		if (got < batch)
			break;
	}

out:
	return allocated;
}

/*
 * Run the attached XDP program on an XSK-backed xdp_buff and dispose of
 * the buffer according to the action.  The caller has already
 * transferred ownership of the xdp_buff to this function.
 *
 * v1 keeps the supported action set intentionally small:
 *   XDP_REDIRECT  -- the expected ZC fast path (packet goes into the
 *                    user-visible RX ring via __xsk_rcv_zc).
 *   XDP_DROP      -- buffer is freed back to the umem.
 *   XDP_PASS/_TX  -- not supported in v1.  PASS would require building
 *                    an skb and copying out of the umem; TX on an
 *                    xsk_buff requires machinery that lands in M4.  Both
 *                    are treated as DROP and counted as such.
 */
static int
vmxnet3_run_xdp_xsk(struct vmxnet3_rx_queue *rq, struct xdp_buff *xdp,
		    struct bpf_prog *prog)
{
	u32 act;
	int err;

	rq->stats.xdp_packets++;
	act = bpf_prog_run_xdp(prog, xdp);

	switch (act) {
	case XDP_REDIRECT:
		err = xdp_do_redirect(rq->adapter->netdev, xdp, prog);
		if (!err) {
			rq->stats.xdp_redirects++;
			return XDP_REDIRECT;
		}
		rq->stats.xdp_drops++;
		xsk_buff_free(xdp);
		return XDP_DROP;
	case XDP_PASS:
	case XDP_TX:
		/* Not supported in v1; treat as drop.  A later revision
		 * will build an skb on PASS and re-DMA the umem chunk into
		 * an internal TX slot on XDP_TX.
		 */
		rq->stats.xdp_drops++;
		xsk_buff_free(xdp);
		return XDP_DROP;
	default:
		bpf_warn_invalid_xdp_action(rq->adapter->netdev, prog, act);
		fallthrough;
	case XDP_ABORTED:
		trace_xdp_exception(rq->adapter->netdev, prog, act);
		rq->stats.xdp_aborted++;
		break;
	case XDP_DROP:
		rq->stats.xdp_drops++;
		break;
	}

	xsk_buff_free(xdp);
	return XDP_DROP;
}

/*
 * NAPI RX completion path for the zero-copy case.
 *
 * Invoked from vmxnet3_rq_rx_complete() when rq->zc_enabled is set.
 * Mirrors the essential structure of that function but is simplified by
 * the v1 constraints: single-buffer packets, ring[0] only, XDP program
 * required (no stack fallback).
 */
int
vmxnet3_rq_rx_complete_zc(struct vmxnet3_rx_queue *rq,
			  struct vmxnet3_adapter *adapter, int quota)
{
	struct Vmxnet3_RxCompDesc *rcd;
	struct bpf_prog *xdp_prog;
	int num_pkts = 0;
	bool need_flush = false;
	int num_to_alloc;

	/* v1 zero-copy is little-endian only: the helper macro
	 * vmxnet3_getRxComp that handles the BE bit-field shuffle lives
	 * privately in vmxnet3_drv.c.  QEMU targets using vmxnet3 are all
	 * little-endian so skipping BE support here is acceptable for the
	 * initial implementation.
	 */
	BUILD_BUG_ON(IS_ENABLED(CONFIG_CPU_BIG_ENDIAN));

	/* NAPI poll context does not implicitly hold rcu_read_lock; take
	 * it explicitly to cover both the program pointer fetch and any
	 * xdp_do_redirect() / xdp_do_flush() invoked below.
	 */
	rcu_read_lock();
	xdp_prog = rcu_dereference(adapter->xdp_bpf_prog);

	rcd = &rq->comp_ring.base[rq->comp_ring.next2proc].rcd;
	while (rcd->gen == rq->comp_ring.gen) {
		struct vmxnet3_rx_buf_info *rbi;
		struct xdp_buff *xdp;
		u32 idx, ring_idx;

		if (num_pkts >= quota)
			break;

		/* Pair with the write ordering in vmxnet3_rq_alloc_rx_buf_xsk
		 * and the QEMU/device side; see gen-bit comment in
		 * vmxnet3_rq_rx_complete().
		 */
		dma_rmb();

		idx = rcd->rxdIdx;
		ring_idx = VMXNET3_GET_RING_IDX(adapter, rcd->rqID);

		if (unlikely(ring_idx != 0)) {
			/* Body ring is not supplied with XSK buffers in v1.
			 * A completion here indicates the device decided to
			 * scatter -- drop and move on.  Caller's mtu-check in
			 * pool_enable makes this unreachable in practice.
			 */
			rq->stats.drop_err++;
			goto advance;
		}

		rbi = &rq->buf_info[0][idx];
		if (unlikely(rbi->buf_type != VMXNET3_RX_BUF_XSK ||
			     !rbi->xsk_xdp)) {
			/* Stale descriptor from a previous non-ZC epoch (or
			 * already consumed).  Shouldn't happen once enable
			 * has fully rebuilt the ring, but stay defensive.
			 */
			goto advance;
		}

		xdp = rbi->xsk_xdp;
		rbi->xsk_xdp = NULL;

		if (unlikely(rcd->err || !rcd->sop || !rcd->eop)) {
			xsk_buff_free(xdp);
			goto advance;
		}

		xsk_buff_set_size(xdp, rcd->len);
		xsk_buff_dma_sync_for_cpu(xdp);

		if (likely(xdp_prog)) {
			int act = vmxnet3_run_xdp_xsk(rq, xdp, xdp_prog);

			if (act == XDP_REDIRECT)
				need_flush = true;
		} else {
			/* No XDP program attached: no place for the packet to
			 * go in v1 (no skb build-and-copy fallback).  Drop
			 * and count.  Users should always attach an XDP prog
			 * before bind()ing an XDP socket in ZC mode anyway.
			 */
			rq->stats.xdp_drops++;
			xsk_buff_free(xdp);
		}

		num_pkts++;

advance:
		rbi->comp_state = VMXNET3_RXD_COMP_DONE;
		vmxnet3_comp_ring_adv_next2proc(&rq->comp_ring);
		rcd = &rq->comp_ring.base[rq->comp_ring.next2proc].rcd;
	}

	/* Refill ring[0] with fresh XSK buffers.  vmxnet3_rq_alloc_rx_buf_xsk
	 * returns short if the umem FILL ring is temporarily drained; that
	 * is handled via need_wakeup in M5.
	 */
	num_to_alloc = vmxnet3_cmd_ring_desc_avail(&rq->rx_ring[0]);
	if (num_to_alloc)
		vmxnet3_rq_alloc_rx_buf_xsk(rq, num_to_alloc);

	/* Tell the device about freshly produced descriptors when the
	 * adapter wants explicit producer updates.
	 */
	dma_wmb();
	if (unlikely(rq->shared->updateRxProd)) {
		VMXNET3_WRITE_BAR0_REG(adapter,
				       adapter->rx_prod_offset + rq->qid * 8,
				       rq->rx_ring[0].next2fill);
	}

	if (need_flush)
		xdp_do_flush();
	rcu_read_unlock();

	return num_pkts;
}

/*
 * Per-queue RX init for the ZC case.  Invoked from vmxnet3_rq_init()
 * instead of the normal page-pool path when rq->zc_enabled is set.
 */
int
vmxnet3_rq_init_xsk(struct vmxnet3_rx_queue *rq,
		    struct vmxnet3_adapter *adapter)
{
	u32 frame_len;
	int err, i;

	if (unlikely(!rq->xsk_pool))
		return -EINVAL;

	frame_len = xsk_pool_get_rx_frame_size(rq->xsk_pool);

	/* Tag ring[0] as XSK; ring[1] is left empty (v1 single-buffer). */
	for (i = 0; i < rq->rx_ring[0].size; i++) {
		rq->buf_info[0][i].buf_type = VMXNET3_RX_BUF_XSK;
		rq->buf_info[0][i].len = frame_len;
		rq->buf_info[0][i].xsk_xdp = NULL;
	}
	for (i = 0; i < rq->rx_ring[1].size; i++) {
		rq->buf_info[1][i].buf_type = VMXNET3_RX_BUF_NONE;
		rq->buf_info[1][i].len = 0;
	}

	for (i = 0; i < 2; i++) {
		rq->rx_ring[i].next2fill = rq->rx_ring[i].next2comp = 0;
		memset(rq->rx_ring[i].base, 0, rq->rx_ring[i].size *
		       sizeof(struct Vmxnet3_RxDesc));
		rq->rx_ring[i].gen = VMXNET3_INIT_GEN;
		rq->rx_ring[i].isOutOfOrder = 0;
	}

	err = xdp_rxq_info_reg(&rq->xdp_rxq, adapter->netdev, rq->qid,
			       rq->napi.napi_id);
	if (err < 0)
		return err;
	err = xdp_rxq_info_reg_mem_model(&rq->xdp_rxq,
					 MEM_TYPE_XSK_BUFF_POOL, NULL);
	if (err) {
		xdp_rxq_info_unreg(&rq->xdp_rxq);
		return err;
	}
	xsk_pool_set_rxq_info(rq->xsk_pool, &rq->xdp_rxq);

	if (vmxnet3_rq_alloc_rx_buf_xsk(rq, rq->rx_ring[0].size - 1) == 0) {
		xdp_rxq_info_unreg(&rq->xdp_rxq);
		return -ENOMEM;
	}

	if (rq->ts_ring.base)
		memset(rq->ts_ring.base, 0,
		       rq->rx_ring[0].size * rq->rx_ts_desc_size);

	rq->comp_ring.next2proc = 0;
	memset(rq->comp_ring.base, 0,
	       rq->comp_ring.size * sizeof(struct Vmxnet3_RxCompDesc));
	rq->comp_ring.gen = VMXNET3_INIT_GEN;

	rq->rx_ctx.skb = NULL;
	return 0;
}

/*
 * Free any XSK buffers still sitting in buf_info[0] slots.  Called from
 * vmxnet3_rq_cleanup() before the ring metadata is reset.  After this
 * runs, the union members (page / skb / xsk_xdp) all read as NULL so
 * the remaining non-XSK cleanup below is a no-op for XSK entries.
 */
void
vmxnet3_rq_cleanup_xsk(struct vmxnet3_rx_queue *rq)
{
	int i;

	if (!rq->rx_ring[0].base || !rq->buf_info[0])
		return;

	for (i = 0; i < rq->rx_ring[0].size; i++) {
		struct vmxnet3_rx_buf_info *rbi = &rq->buf_info[0][i];

		if (rbi->buf_type == VMXNET3_RX_BUF_XSK && rbi->xsk_xdp) {
			xsk_buff_free(rbi->xsk_xdp);
			rbi->xsk_xdp = NULL;
		}
	}
}

/*
 * Enable zero-copy on one RX queue by attaching the supplied umem pool.
 *
 * Validates the pool, DMA-maps it for this PCI device, then (if the
 * netdev is running) performs the quiesce / destroy / recreate /
 * activate dance that existing XDP attach already uses in
 * vmxnet3_xdp_set().  A whole-device rebuild is overkill for binding a
 * single queue but is the simplest correct path given the vmxnet3
 * control model, and it matches the granularity of XDP_SETUP_PROG.
 */
static int
vmxnet3_xsk_pool_enable(struct vmxnet3_adapter *adapter,
			struct xsk_buff_pool *pool, u16 qid)
{
	struct net_device *dev = adapter->netdev;
	bool running;
	u32 frame_len;
	int err;

	if (qid >= adapter->num_rx_queues)
		return -EINVAL;
	if (!pool)
		return -EINVAL;

	/* The RX ring uses single-buffer packets in ZC.  Require that the
	 * umem chunk can hold the full frame.
	 */
	frame_len = xsk_pool_get_rx_frame_size(pool);
	if (frame_len < dev->mtu + VMXNET3_MAX_ETH_HDR_SIZE)
		return -EINVAL;

	err = vmxnet3_xsk_ensure_pool_table(adapter);
	if (err)
		return err;

	if (adapter->xsk_pools[qid])
		return -EBUSY;

	err = xsk_pool_dma_map(pool, &adapter->pdev->dev, 0);
	if (err)
		return err;

	running = netif_running(dev);
	if (running)
		vmxnet3_quiesce_dev(adapter);

	adapter->xsk_pools[qid] = pool;
	adapter->rx_queue[qid].xsk_pool = pool;
	adapter->rx_queue[qid].zc_enabled = true;
	if (qid < adapter->num_tx_queues)
		adapter->tx_queue[qid].xsk_pool = pool;

	if (running) {
		vmxnet3_rq_destroy_all(adapter);
		vmxnet3_adjust_rx_ring_size(adapter);
		err = vmxnet3_rq_create_all(adapter);
		if (err)
			goto err_activate;
		err = vmxnet3_activate_dev(adapter);
		if (err)
			goto err_activate;
	}

	return 0;

err_activate:
	/* On rebuild failure undo everything we just wired up.  The
	 * netdev is left in a sorry state -- identical to the existing
	 * vmxnet3_xdp_set() failure mode -- and the caller is expected
	 * to unload / reload the module as recovery.
	 */
	adapter->xsk_pools[qid] = NULL;
	adapter->rx_queue[qid].xsk_pool = NULL;
	adapter->rx_queue[qid].zc_enabled = false;
	if (qid < adapter->num_tx_queues)
		adapter->tx_queue[qid].xsk_pool = NULL;
	xsk_pool_dma_unmap(pool, 0);
	return err;
}

/*
 * Disable a previously-bound umem pool on one RX queue.
 *
 * Idempotent: safe to call when no pool has ever been attached, so
 * vmxnet3_remove_device() can iterate every qid without caring whether
 * it was actually used.
 */
static int
vmxnet3_xsk_pool_disable(struct vmxnet3_adapter *adapter, u16 qid)
{
	struct net_device *dev = adapter->netdev;
	struct xsk_buff_pool *pool;
	bool running;
	int err = 0;

	if (qid >= adapter->num_rx_queues)
		return -EINVAL;
	if (!adapter->xsk_pools)
		return 0;

	pool = adapter->xsk_pools[qid];
	if (!pool)
		return 0;

	running = netif_running(dev);
	if (running)
		vmxnet3_quiesce_dev(adapter);

	adapter->xsk_pools[qid] = NULL;
	adapter->rx_queue[qid].xsk_pool = NULL;
	adapter->rx_queue[qid].zc_enabled = false;
	if (qid < adapter->num_tx_queues)
		adapter->tx_queue[qid].xsk_pool = NULL;

	if (running) {
		vmxnet3_rq_destroy_all(adapter);
		vmxnet3_adjust_rx_ring_size(adapter);
		err = vmxnet3_rq_create_all(adapter);
		if (!err)
			err = vmxnet3_activate_dev(adapter);
	}

	xsk_pool_dma_unmap(pool, 0);
	return err;
}

/*
 * Release the xsk_pools[] table at netdev teardown.
 *
 * Must run after every RX queue has been unbound; this routine iterates
 * qids defensively and then frees the table itself.
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

/*
 * Drain up to 'budget' descriptors from the userspace TX ring of the
 * bound XSK pool and commit them to the device's TX command ring.
 *
 * Called from NAPI poll (vmxnet3_do_poll / vmxnet3_poll_rx_only) before
 * the TX completion sweep so the freshly-submitted frames can be
 * reaped in the same cycle on fast adapters.  Takes tq->tx_lock to
 * serialise against ndo_start_xmit and vmxnet3_xdp_xmit_frame which
 * both write the same ring.
 *
 * Returns the number of descriptors submitted.
 */
int
vmxnet3_xmit_zc(struct vmxnet3_tx_queue *tq, unsigned int budget)
{
	struct xsk_buff_pool *pool = tq->xsk_pool;
	struct vmxnet3_adapter *adapter;
	struct xdp_desc desc;
	unsigned int sent = 0;

	if (!pool)
		return 0;

	adapter = tq->adapter;
	if (test_bit(VMXNET3_STATE_BIT_QUIESCED, &adapter->state) ||
	    test_bit(VMXNET3_STATE_BIT_RESETTING, &adapter->state))
		return 0;

	spin_lock(&tq->tx_lock);

	while (sent < budget) {
		struct vmxnet3_tx_buf_info *tbi;
		union Vmxnet3_GenericDesc *gd;
		dma_addr_t dma;
		u32 dw2;

		if (!vmxnet3_cmd_ring_desc_avail(&tq->tx_ring)) {
			tq->stats.tx_ring_full++;
			break;
		}
		if (!xsk_tx_peek_desc(pool, &desc))
			break;

		dma = xsk_buff_raw_get_dma(pool, desc.addr);
		xsk_buff_raw_dma_sync_for_device(pool, dma, desc.len);

		tbi = tq->buf_info + tq->tx_ring.next2fill;
		gd  = tq->tx_ring.base + tq->tx_ring.next2fill;

		tbi->map_type = VMXNET3_MAP_XSK;
		tbi->dma_addr = dma;
		tbi->len      = desc.len;
		tbi->xsk_addr = desc.addr;
		tbi->sop_idx  = tq->tx_ring.next2fill;

		/* Build the descriptor with the inverted gen bit first, so
		 * QEMU cannot observe a half-written entry while the payload
		 * fields are in flight.
		 */
		dw2  = (tq->tx_ring.gen ^ 0x1) << VMXNET3_TXD_GEN_SHIFT;
		dw2 |= desc.len;

		gd->txd.addr  = cpu_to_le64(dma);
		gd->dword[2]  = cpu_to_le32(dw2);
		gd->dword[3]  = cpu_to_le32(VMXNET3_TXD_CQ | VMXNET3_TXD_EOP);
		gd->txd.om    = 0;
		gd->txd.msscof = 0;
		gd->txd.hlen  = 0;
		gd->txd.ti    = 0;

		vmxnet3_cmd_ring_adv_next2fill(&tq->tx_ring);

		/* Publish the entry by flipping the gen bit last.  Matches
		 * the ordering used by vmxnet3_xdp_xmit_frame() so both
		 * producers look identical to QEMU.
		 */
		dma_wmb();
		gd->dword[2] = cpu_to_le32(le32_to_cpu(gd->dword[2]) ^
					   VMXNET3_TXD_GEN);

		sent++;
	}

	if (sent) {
		xsk_tx_release(pool);

		/* Doorbell the device.  txNumDeferred is reset because XSK
		 * submissions are not skb-batched; the paravirt backend
		 * polls this on a timer so the exact value does not matter
		 * as long as it stays below threshold.
		 */
		tq->shared->txNumDeferred = 0;
		VMXNET3_WRITE_BAR0_REG(adapter,
				       VMXNET3_REG_TXPROD + tq->qid * 8,
				       tq->tx_ring.next2fill);
	}

	spin_unlock(&tq->tx_lock);
	return sent;
}

void
vmxnet3_xsk_tx_completed(struct vmxnet3_tx_queue *tq, u32 n)
{
	if (tq->xsk_pool && n)
		xsk_tx_completed(tq->xsk_pool, n);
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

int
vmxnet3_rq_init_xsk(struct vmxnet3_rx_queue *rq,
		    struct vmxnet3_adapter *adapter)
{
	return -EOPNOTSUPP;
}

void
vmxnet3_rq_cleanup_xsk(struct vmxnet3_rx_queue *rq)
{
}

int
vmxnet3_rq_alloc_rx_buf_xsk(struct vmxnet3_rx_queue *rq, int num_to_alloc)
{
	return 0;
}

int
vmxnet3_xmit_zc(struct vmxnet3_tx_queue *tq, unsigned int budget)
{
	return 0;
}

void
vmxnet3_xsk_tx_completed(struct vmxnet3_tx_queue *tq, u32 n)
{
}

#endif /* CONFIG_XDP_SOCKETS */

int
vmxnet3_xsk_wakeup(struct net_device *dev, u32 qid, u32 flags)
{
	/* M1 stub: wakeup never scheduled because M5 hasn't wired the
	 * need_wakeup protocol yet.  With current M4, TX submission
	 * happens on every NAPI tick regardless, so userspace using
	 * XDP_USE_NEED_WAKEUP will observe a stall until poll()/sendto()
	 * returns of its own accord.
	 */
	return -EOPNOTSUPP;
}
