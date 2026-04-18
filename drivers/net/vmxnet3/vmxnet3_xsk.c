// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Linux driver for VMware's vmxnet3 ethernet NIC.
 *
 * AF_XDP zero-copy data and control paths.
 *
 * Copyright (C) 2026, the vmxnet3 XSK project contributors.
 * Maintained by: pv-drivers@vmware.com
 *
 * Milestone layout (M1 → M5):
 *   M1: this file provides stubs. vmxnet3_xsk_pool_setup() and
 *       .ndo_xsk_wakeup return -EOPNOTSUPP so a ZC bind() fails cleanly
 *       rather than hanging. No behavioural change versus mainline.
 *   M2: vmxnet3_xsk_pool_setup() becomes real (pool DMA map, quiesce-
 *       rebuild the affected RX queue).
 *   M3: vmxnet3_rq_rx_complete_zc() plus vmxnet3_rq_alloc_rx_buf_xsk().
 *   M4: vmxnet3_xmit_zc() plus TX completion hookup.
 *   M5: vmxnet3_xsk_wakeup() plus need_wakeup signalling.
 *
 * The file is compiled unconditionally so the symbols always exist. When
 * CONFIG_XDP_SOCKETS is disabled the bodies are trivial and the XSK
 * kernel APIs are never touched.
 */

#include <linux/errno.h>
#include <linux/netdevice.h>

#ifdef CONFIG_XDP_SOCKETS
#include <net/xdp_sock_drv.h>
#endif

#include "vmxnet3_int.h"
#include "vmxnet3_xsk.h"

int
vmxnet3_xsk_pool_setup(struct vmxnet3_adapter *adapter,
		       struct xsk_buff_pool *pool, u16 qid)
{
#ifdef CONFIG_XDP_SOCKETS
	/* M1 stub: control path arrives here but is not yet implemented.
	 * M2 will return 0 on a valid enable/disable and wire DMA mapping.
	 */
	return -EOPNOTSUPP;
#else
	return -EOPNOTSUPP;
#endif
}

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
	/* M1 stub: RX fast path must be callable without effect. In M2 the
	 * control path refuses enable, so this function stays unreachable
	 * until M3 delivers the real implementation.
	 */
	return 0;
}
