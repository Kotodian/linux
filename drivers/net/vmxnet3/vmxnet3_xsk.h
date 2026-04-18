/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Linux driver for VMware's vmxnet3 ethernet NIC.
 *
 * AF_XDP zero-copy support.
 *
 * Copyright (C) 2026, the vmxnet3 XSK project contributors.
 * Maintained by: pv-drivers@vmware.com
 */

#ifndef _VMXNET3_XSK_H
#define _VMXNET3_XSK_H

#include <linux/types.h>

struct net_device;
struct vmxnet3_adapter;
struct vmxnet3_rx_queue;
struct vmxnet3_tx_queue;
struct xsk_buff_pool;

/* These prototypes are always visible. The symbols are provided by
 * vmxnet3_xsk.c, whose function bodies are compiled out (returning
 * -EOPNOTSUPP / 0) when CONFIG_XDP_SOCKETS is disabled. Call sites can
 * therefore invoke them unconditionally.
 */
int vmxnet3_xsk_pool_setup(struct vmxnet3_adapter *adapter,
			   struct xsk_buff_pool *pool, u16 qid);
int vmxnet3_xsk_wakeup(struct net_device *dev, u32 qid, u32 flags);
int vmxnet3_xmit_zc(struct vmxnet3_tx_queue *tq, unsigned int budget);
int vmxnet3_rq_rx_complete_zc(struct vmxnet3_rx_queue *rq,
			      struct vmxnet3_adapter *adapter, int quota);

/* Per-queue ZC setup / teardown helpers used from vmxnet3_rq_init() and
 * vmxnet3_rq_cleanup() when rq->zc_enabled is set.  When ZC is not
 * enabled they are not called.  Each is also present as a trivial
 * stub when CONFIG_XDP_SOCKETS is disabled.
 */
int vmxnet3_rq_init_xsk(struct vmxnet3_rx_queue *rq,
			struct vmxnet3_adapter *adapter);
void vmxnet3_rq_cleanup_xsk(struct vmxnet3_rx_queue *rq);
int vmxnet3_rq_alloc_rx_buf_xsk(struct vmxnet3_rx_queue *rq, int num_to_alloc);

/* Bulk-complete 'n' XSK-backed TX descriptors to the bound pool.  Called
 * from the TX completion path.  No-op when the TX queue has no pool.
 */
void vmxnet3_xsk_tx_completed(struct vmxnet3_tx_queue *tq, u32 n);

/* Release the per-qid pool table on netdev teardown.  Safe to call even
 * when no ZC socket ever attached.
 */
void vmxnet3_xsk_free_pool_table(struct vmxnet3_adapter *adapter);

#endif /* _VMXNET3_XSK_H */
