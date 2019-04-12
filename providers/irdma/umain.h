/*******************************************************************************
 *
 * Copyright (c) 2018 - 2019 Intel Corporation.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenFabrics.org BSD license below:
 *
 *   Redistribution and use in source and binary forms, with or
 *   without modification, are permitted provided that the following
 *   conditions are met:
 *
 *    - Redistributions of source code must retain the above
 *	copyright notice, this list of conditions and the following
 *	disclaimer.
 *
 *    - Redistributions in binary form must reproduce the above
 *	copyright notice, this list of conditions and the following
 *	disclaimer in the documentation and/or other materials
 *	provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 ******************************************************************************/

#ifndef IRDMA_UMAIN_H
#define IRDMA_UMAIN_H

#include <inttypes.h>
#include <stddef.h>
#include <endian.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <infiniband/driver.h>

#include "osdep.h"
#include "irdma.h"
#include "defs.h"
#include "i40iw_hw.h"
#include "status.h"
#include "user.h"

#define PFX	"libirdma-"

#define IRDMA_BASE_PUSH_PAGE		1
#define IRDMA_U_MINCQ_SIZE		4
#define IRDMA_DB_SHADOW_AREA_SIZE	64
#define IRDMA_DB_CQ_OFFSET		64

enum irdma_uhca_type {
	INTEL_irdma
};

struct irdma_udevice {
	struct verbs_device ibv_dev;
	enum irdma_uhca_type hca_type;
	int page_size;
};

struct irdma_uah {
	struct ibv_ah ibv_ah;
	uint32_t ah_id;
	struct ibv_global_route grh;
};

struct irdma_upd {
	struct ibv_pd ibv_pd;
	void *db;
	void *arm_cq_page;
	void *arm_cq;
	uint32_t pd_id;
};

struct irdma_uvcontext {
	struct verbs_context ibv_ctx;
	struct irdma_upd *iwupd;
	struct irdma_uk_attrs uk_attrs;
	struct irdma_dev_uk dev;
	int abi_ver;
};

struct irdma_uqp;

struct irdma_cq_buf {
	struct irdma_cq_uk cq;
	struct verbs_mr vmr;
	struct list_node list;
};

struct irdma_ucq {
	struct ibv_cq ibv_cq;
	struct verbs_mr vmr;
	struct verbs_mr vmr_shadow_area;
	pthread_spinlock_t lock;
	bool is_armed;
	bool skip_arm;
	bool arm_sol;
	bool skip_sol;
	int comp_vector;
	struct irdma_uqp *uqp;
	struct irdma_cq_uk cq;
	struct list_head resize_list;
};

struct irdma_uqp {
	struct ibv_qp ibv_qp;
	struct irdma_ucq *send_cq;
	struct irdma_ucq *recv_cq;
	struct verbs_mr vmr;
	uint32_t irdma_drv_opt;
	pthread_spinlock_t lock;
	uint16_t sq_sig_all;
	uint16_t qperr;
	uint16_t rsvd;
	uint32_t pending_rcvs;
	uint32_t wq_size;
	struct ibv_recv_wr *pend_rx_wr;
	struct irdma_qp_uk qp;
	enum ibv_qp_type qp_type;
};

#define to_irdma_uxxx(xxx, type)                                               \
	container_of(ib##xxx, struct irdma_u##type, ibv_##xxx)

static inline struct irdma_udevice *to_irdma_udev(struct ibv_device *ibdev)
{
	return container_of(ibdev, struct irdma_udevice, ibv_dev.device);
}

static inline struct irdma_uvcontext *to_irdma_uctx(struct ibv_context *ibctx)
{
	return container_of(ibctx, struct irdma_uvcontext, ibv_ctx.context);
}

static inline struct irdma_uah *to_irdma_uah(struct ibv_ah *ibah)
{
	return to_irdma_uxxx(ah, ah);
}

static inline struct irdma_upd *to_irdma_upd(struct ibv_pd *ibpd)
{
	return to_irdma_uxxx(pd, pd);
}

static inline struct irdma_ucq *to_irdma_ucq(struct ibv_cq *ibcq)
{
	return to_irdma_uxxx(cq, cq);
}

static inline struct irdma_uqp *to_irdma_uqp(struct ibv_qp *ibqp)
{
	return to_irdma_uxxx(qp, qp);
}

/* irdma_uverbs.c */
int irdma_uquery_device(struct ibv_context *, struct ibv_device_attr *);
int irdma_uquery_port(struct ibv_context *context, uint8_t port,
		      struct ibv_port_attr *attr);
struct ibv_pd *irdma_ualloc_pd(struct ibv_context *context);
int irdma_ufree_pd(struct ibv_pd *pd);
struct ibv_mr *irdma_ureg_mr(struct ibv_pd *pd, void *addr, size_t length,
			     int access);
int irdma_udereg_mr(struct verbs_mr *vmr);
struct ibv_mw *irdma_ualloc_mw(struct ibv_pd *pd, enum ibv_mw_type type);
int irdma_ubind_mw(struct ibv_qp *qp, struct ibv_mw *mw,
		   struct ibv_mw_bind *mw_bind);
int irdma_udealloc_mw(struct ibv_mw *mw);
struct ibv_cq *irdma_ucreate_cq(struct ibv_context *context, int cqe,
				struct ibv_comp_channel *channel,
				int comp_vector);
int irdma_uresize_cq(struct ibv_cq *cq, int cqe);
int irdma_udestroy_cq(struct ibv_cq *cq);
int irdma_upoll_cq(struct ibv_cq *cq, int entries, struct ibv_wc *entry);
int irdma_uarm_cq(struct ibv_cq *cq, int solicited);
void irdma_cq_event(struct ibv_cq *cq);
struct ibv_qp *irdma_ucreate_qp(struct ibv_pd *pd,
				struct ibv_qp_init_attr *attr);
int irdma_uquery_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask,
		    struct ibv_qp_init_attr *init_attr);
int irdma_umodify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		     int attr_mask);
int irdma_udestroy_qp(struct ibv_qp *qp);
int irdma_upost_send(struct ibv_qp *ib_qp, struct ibv_send_wr *ib_wr,
		     struct ibv_send_wr **bad_wr);
int irdma_upost_recv(struct ibv_qp *ib_qp, struct ibv_recv_wr *ib_wr,
		     struct ibv_recv_wr **bad_wr);
struct ibv_ah *irdma_ucreate_ah(struct ibv_pd *ibpd, struct ibv_ah_attr *attr);
int irdma_udestroy_ah(struct ibv_ah *ibah);
int irdma_uattach_mcast(struct ibv_qp *qp, const union ibv_gid *gid,
			uint16_t lid);
int irdma_udetach_mcast(struct ibv_qp *qp, const union ibv_gid *gid,
			uint16_t lid);
void irdma_async_event(struct ibv_context *context, struct ibv_async_event *event);
void irdma_set_hw_attrs(struct irdma_hw_attrs *attrs);
#endif /* IRDMA_UMAIN_H */
