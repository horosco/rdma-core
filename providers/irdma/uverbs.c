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

#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <malloc.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "umain.h"
#include "abi.h"

/**
 * irdma_uquery_device - call driver to query device for max resources
 * @context: user context for the device
 * @attr: where to save all the mx resources from the driver
 **/
int irdma_uquery_device(struct ibv_context *context,
			struct ibv_device_attr *attr)
{
	struct ibv_query_device cmd;
	uint64_t irdma_fw_ver;
	int ret;
	unsigned int minor, major;

	ret = ibv_cmd_query_device(context, attr, &irdma_fw_ver, &cmd,
				   sizeof(cmd));
	if (ret) {
		fprintf(stderr, PFX "%s: query device failed and returned status code: %d\n",
			__func__, ret);
		return ret;
	}

	major = (irdma_fw_ver >> 16) & 0xffff;
	minor = irdma_fw_ver & 0xffff;

	snprintf(attr->fw_ver, sizeof(attr->fw_ver), "%d.%d", major, minor);

	return 0;
}

/**
 * irdma_uquery_port - get port attributes (msg size, lnk, mtu...)
 * @context: user context of the device
 * @port: port for the attributes
 * @attr: to return port attributes
 **/
int irdma_uquery_port(struct ibv_context *context, uint8_t port,
		      struct ibv_port_attr *attr)
{
	struct ibv_query_port cmd;

	return ibv_cmd_query_port(context, port, attr, &cmd, sizeof(cmd));
}

/**
 * irdma_ualloc_pd - allocates protection domain and return pd ptr
 * @context: user context of the device
 **/
struct ibv_pd *irdma_ualloc_pd(struct ibv_context *context)
{
	struct ibv_alloc_pd cmd;
	struct irdma_ualloc_pd_resp resp = {};
	struct irdma_upd *iwupd;
	void *map;

	iwupd = malloc(sizeof(*iwupd));
	if (!iwupd)
		return NULL;

	if (ibv_cmd_alloc_pd(context, &iwupd->ibv_pd, &cmd, sizeof(cmd),
			     &resp.ibv_resp, sizeof(resp)))
		goto err_free;

	iwupd->pd_id = resp.pd_id;
	map = mmap(NULL, IRDMA_HW_PAGE_SIZE, PROT_WRITE | PROT_READ, MAP_SHARED,
		   context->cmd_fd, 0);
	if (map == MAP_FAILED) {
		ibv_cmd_dealloc_pd(&iwupd->ibv_pd);
		goto err_free;
	}

	iwupd->db = map;
	return &iwupd->ibv_pd;

err_free:
	free(iwupd);
	return NULL;
}

/**
 * irdma_ufree_pd - free pd resources
 * @pd: pd to free resources
 */
int irdma_ufree_pd(struct ibv_pd *pd)
{
	struct irdma_upd *iwupd;
	int ret;

	iwupd = to_irdma_upd(pd);
	ret = ibv_cmd_dealloc_pd(pd);
	if (ret)
		return ret;

	munmap((void *)iwupd->db, IRDMA_HW_PAGE_SIZE);
	free(iwupd);

	return 0;
}

/**
 * irdma_ureg_mr - register user memory region
 * @pd: pd for the mr
 * @addr: user address of the memory region
 * @length: length of the memory
 * @access: access allowed on this mr
 */
struct ibv_mr *irdma_ureg_mr(struct ibv_pd *pd, void *addr, size_t length,
			     int access)
{
	struct verbs_mr *vmr;
	struct irdma_ureg_mr cmd;
	struct ib_uverbs_reg_mr_resp resp;

	vmr = malloc(sizeof(*vmr));
	if (!vmr)
		return NULL;

	cmd.reg_type = IW_MEMREG_TYPE_MEM;
	if (ibv_cmd_reg_mr(pd, addr, length, (uintptr_t)addr, access, vmr,
			   &cmd.ibv_cmd, sizeof(cmd), &resp, sizeof(resp))) {
		fprintf(stderr, PFX "%s: Failed to register memory\n", __func__);
		free(vmr);
		return NULL;
	}

	return &vmr->ibv_mr;
}

/**
 * irdma_udereg_mr - re-register memory region
 * @vmr: mr that was allocated
 */
int irdma_udereg_mr(struct verbs_mr *vmr)
{
	int ret;

	ret = ibv_cmd_dereg_mr(vmr);
	if (ret)
		return ret;

	free(vmr);

	return 0;
}

/**
 * irdma_ualloc_mw - allocate memory window
 * @pd: protection domain
 * @type: memory window type
 */
struct ibv_mw *irdma_ualloc_mw(struct ibv_pd *pd, enum ibv_mw_type type)
{
	struct ibv_mw *mw;
	struct ibv_alloc_mw cmd;
	struct ib_uverbs_alloc_mw_resp resp;

	mw = calloc(1, sizeof(*mw));
	if (!mw)
		return NULL;

	if (ibv_cmd_alloc_mw(pd, type, mw, &cmd, sizeof(cmd), &resp,
			     sizeof(resp))) {
		fprintf(stderr, PFX "%s: Failed to dealloc memory window\n",
			__func__);
		free(mw);
		return NULL;
	}

	return mw;
}

/**
 * irdma_ubind_mw - bind a memory window
 * @qp: qp to post WR
 * @mw: memory window to bind
 * @mw_bind: bind info
 */
int irdma_ubind_mw(struct ibv_qp *qp, struct ibv_mw *mw,
		   struct ibv_mw_bind *mw_bind)
{
	struct ibv_send_wr wr = {};
	struct ibv_send_wr *bad_wr;
	int err;

	memset(&wr, 0, sizeof(wr));

	wr.opcode = IBV_WR_BIND_MW;
	wr.bind_mw.bind_info = mw_bind->bind_info;
	wr.bind_mw.mw = mw;
	if (mw->type == IBV_MW_TYPE_1)
		wr.bind_mw.rkey = ibv_inc_rkey(mw->rkey);
	else
		wr.bind_mw.rkey = mw->rkey;

	wr.wr_id = mw_bind->wr_id;
	wr.send_flags = mw_bind->send_flags;

	err = irdma_upost_send(qp, &wr, &bad_wr);
	if (!err)
		mw->rkey = wr.bind_mw.rkey;

	return err;
}

/**
 * irdma_udealloc_mw - deallocate memory window
 * @mw: memory window to dealloc
 */
int irdma_udealloc_mw(struct ibv_mw *mw)
{
	int ret;

	ret = ibv_cmd_dealloc_mw(mw);
	if (ret) {
		fprintf(stderr, PFX "%s: Failed to dealloc memory windo\n", __func__);
		return ret;
	}

	free(mw);

	return 0;
}

/**
 * irdma_num_of_pages - number of pages needed
 * @size: size for number of pages
 */
static inline u32 irdma_num_of_pages(u32 size)
{
	return (size + 4095) >> 12;
}

/**
 * irdma_ucreate_cq - create completion queue for user app
 * @context: user context of the device
 * @cqe: number of cq entries in the cq ring
 * @channel: channel info (context, refcnt..)
 * @comp_vector: save in ucq struct
 */
struct ibv_cq *irdma_ucreate_cq(struct ibv_context *context, int cqe,
				struct ibv_comp_channel *channel,
				int comp_vector)
{
	struct irdma_ucq *iwucq;
	struct irdma_ucreate_cq cmd = {};
	struct irdma_ucreate_cq_resp resp = {};
	struct irdma_cq_uk_init_info info = {};
	struct irdma_ureg_mr reg_mr_cmd = {};
	struct ib_uverbs_reg_mr_resp reg_mr_resp = {};
	struct irdma_ureg_mr reg_mr_shadow_cmd = {};
	struct ib_uverbs_reg_mr_resp reg_mr_shadow_resp = {};
	struct irdma_uvcontext *iwvctx = to_irdma_uctx(context);
	struct irdma_uk_attrs *uk_attrs = &iwvctx->uk_attrs;
	u32 cqe_struct_size;
	u32 totalsize;
	u32 cq_pages;
	u16 shadow_pages;
	int ret;

	if (cqe > uk_attrs->max_hw_cq_size)
		return NULL;

	cqe++;
	if (uk_attrs->hw_rev > IRDMA_GEN_1)
		cqe *= 2;

	iwucq = calloc(1, sizeof(*iwucq));
	if (!iwucq)
		return NULL;

	if (pthread_spin_init(&iwucq->lock, PTHREAD_PROCESS_PRIVATE)) {
		free(iwucq);
		return NULL;
	}

	cqe++;
	if (cqe < IRDMA_U_MINCQ_SIZE)
		cqe = IRDMA_U_MINCQ_SIZE;

	info.cq_size = cqe;
	iwucq->comp_vector = comp_vector;
	list_head_init(&iwucq->resize_list);
	cqe_struct_size = sizeof(struct irdma_cqe);
	cq_pages = irdma_num_of_pages(info.cq_size * cqe_struct_size);

	if (uk_attrs->feature_flags & IRDMA_FEATURE_CQ_RESIZE)
		totalsize = cq_pages << 12;
	else
		totalsize = (cq_pages << 12) + IRDMA_DB_SHADOW_AREA_SIZE;

	info.cq_base = memalign(IRDMA_HW_PAGE_SIZE, totalsize);
	if (!info.cq_base)
		goto err;

	memset(info.cq_base, 0, totalsize);
	reg_mr_cmd.reg_type = IW_MEMREG_TYPE_CQ;
	reg_mr_cmd.cq_pages = cq_pages;

	ret = ibv_cmd_reg_mr(&iwvctx->iwupd->ibv_pd, (void *)info.cq_base,
			     totalsize, (uintptr_t)info.cq_base,
			     IBV_ACCESS_LOCAL_WRITE, &iwucq->vmr,
			     &reg_mr_cmd.ibv_cmd, sizeof(reg_mr_cmd),
			     &reg_mr_resp, sizeof(reg_mr_resp));
	if (ret) {
		fprintf(stderr, PFX "%s: failed to pin memory for CQ\n",
			__func__);
		goto err;
	}
	iwucq->vmr.ibv_mr.pd = &iwvctx->iwupd->ibv_pd;

	if (uk_attrs->feature_flags & IRDMA_FEATURE_CQ_RESIZE) {
		shadow_pages = irdma_num_of_pages(IRDMA_DB_SHADOW_AREA_SIZE);
		info.shadow_area = memalign(IRDMA_HW_PAGE_SIZE,
					    IRDMA_DB_SHADOW_AREA_SIZE);
		if (!info.shadow_area)
			goto err_dereg_mr;

		memset(info.shadow_area, 0, IRDMA_DB_SHADOW_AREA_SIZE);
		reg_mr_shadow_cmd.reg_type = IW_MEMREG_TYPE_CQ;
		reg_mr_shadow_cmd.cq_pages = shadow_pages;

		ret = ibv_cmd_reg_mr(&iwvctx->iwupd->ibv_pd, (void *)info.shadow_area,
				     IRDMA_DB_SHADOW_AREA_SIZE, (uintptr_t)info.shadow_area,
				     IBV_ACCESS_LOCAL_WRITE, &iwucq->vmr_shadow_area,
				     &reg_mr_shadow_cmd.ibv_cmd, sizeof(reg_mr_shadow_cmd),
				     &reg_mr_shadow_resp, sizeof(reg_mr_shadow_resp));
		if (ret) {
			fprintf(stderr, PFX "%s: failed to pin memory for CQ shadow\n",
				__func__);
			goto err_dereg_mr;
		}
		iwucq->vmr_shadow_area.ibv_mr.pd = &iwvctx->iwupd->ibv_pd;

	} else {
		info.shadow_area = (__le64 *)((u8 *)info.cq_base + (cq_pages << 12));
	}

	cmd.user_cq_buf = (__u64)((uintptr_t)info.cq_base);
	cmd.user_shadow_area = (__u64)((uintptr_t)info.shadow_area);
	ret = ibv_cmd_create_cq(context, info.cq_size, channel, comp_vector,
				&iwucq->ibv_cq, &cmd.ibv_cmd, sizeof(cmd),
				&resp.ibv_resp, sizeof(resp));
	if (ret) {
		fprintf(stderr, PFX "%s: failed to create CQ\n", __func__);
		goto err_dereg_mr;
	}

	info.cq_id = (uint16_t)resp.cq_id;
	info.cqe_alloc_db = (u32 *)((u8 *)iwvctx->iwupd->db + IRDMA_DB_CQ_OFFSET);
	ret = iwvctx->dev.ops_uk.iw_cq_uk_init(&iwucq->cq, &info);
	if (!ret)
		return &iwucq->ibv_cq;
	else
		fprintf(stderr, PFX "%s: failed to initialize CQ, status %d\n",
			__func__, ret);

err_dereg_mr:
	ibv_cmd_dereg_mr(&iwucq->vmr);
	if (iwucq->vmr_shadow_area.ibv_mr.handle)
		ibv_cmd_dereg_mr(&iwucq->vmr_shadow_area);
err:
	if (info.cq_base)
		free(info.cq_base);
	if (pthread_spin_destroy(&iwucq->lock))
		return NULL;

	free(iwucq);

	return NULL;
}

/**
 * irdma_free_cq_buf - free memory for cq buffer
 * @cq_buf: cq buf to free
 */
static void irdma_free_cq_buf(struct irdma_cq_buf *cq_buf)
{
	ibv_cmd_dereg_mr(&cq_buf->vmr);
	free(cq_buf->cq.cq_base);
	free(cq_buf);
}

/**
 * irdma_process_resize_list - process the cq list to remove buffers
 * @iwucq: cq which owns the list
 * @lcqe_buf: cq buf where the last cqe is found
 */
static int irdma_process_resize_list(struct irdma_ucq *iwucq,
				     struct irdma_cq_buf *lcqe_buf)
{
	struct irdma_cq_buf *cq_buf, *next;
	int cq_cnt = 0;

	list_for_each_safe(&iwucq->resize_list, cq_buf, next, list) {
		if (cq_buf == lcqe_buf)
			return cq_cnt;

		list_del(&cq_buf->list);
		irdma_free_cq_buf(cq_buf);
		cq_cnt++;
	}

	return cq_cnt;
}

/**
 * irdma_udestroy_cq - destroys cq
 * @cq: ptr to cq to be destroyed
 */
int irdma_udestroy_cq(struct ibv_cq *cq)
{
	struct irdma_ucq *iwucq = to_irdma_ucq(cq);
	struct irdma_uvcontext *iwvctx = to_irdma_uctx(cq->context);
	struct irdma_uk_attrs *uk_attrs = &iwvctx->uk_attrs;
	int ret;

	ret = pthread_spin_destroy(&iwucq->lock);
	if (ret)
		goto err;

	irdma_process_resize_list(iwucq, NULL);
	ret = ibv_cmd_destroy_cq(cq);
	if (ret)
		goto err;

	ibv_cmd_dereg_mr(&iwucq->vmr);
	free(iwucq->cq.cq_base);

	if (uk_attrs->feature_flags & IRDMA_FEATURE_CQ_RESIZE) {
		ibv_cmd_dereg_mr(&iwucq->vmr_shadow_area);
		free(iwucq->cq.shadow_area);
	}
	free(iwucq);
	return 0;

err:
	fprintf(stderr, PFX "%s: failed to destroy CQ, status %d\n",
		__func__, ret);

	return ret;
}

/**
 * irdma_process_cqe - process cqe info
 * @entry - processed cqe
 * @cq_poll_info - cqe info
 */
static void irdma_process_cqe(struct ibv_wc *entry,
			      struct irdma_cq_poll_info *cq_poll_info)
{
	struct irdma_qp_uk *qp;
	struct ibv_qp *ib_qp;

	entry->wc_flags = 0;
	entry->wr_id = cq_poll_info->wr_id;

	if (cq_poll_info->error) {
		entry->status = IBV_WC_WR_FLUSH_ERR;
		entry->vendor_err = cq_poll_info->major_err << 16 |
				    cq_poll_info->minor_err;
	} else {
		entry->status = IBV_WC_SUCCESS;
		if (cq_poll_info->imm_valid) {
			entry->imm_data = htonl(cq_poll_info->imm_data);
			entry->wc_flags |= IBV_WC_WITH_IMM;
		}
	}

	switch (cq_poll_info->op_type) {
	case IRDMA_OP_TYPE_RDMA_WRITE:
		entry->opcode = IBV_WC_RDMA_WRITE;
		break;
	case IRDMA_OP_TYPE_RDMA_READ_INV_STAG:
	case IRDMA_OP_TYPE_RDMA_READ:
		entry->opcode = IBV_WC_RDMA_READ;
		break;
	case IRDMA_OP_TYPE_SEND_SOL:
	case IRDMA_OP_TYPE_SEND_SOL_INV:
	case IRDMA_OP_TYPE_SEND_INV:
	case IRDMA_OP_TYPE_SEND:
		entry->opcode = IBV_WC_SEND;
		if (cq_poll_info->stag_invalid_set)
			entry->invalidated_rkey = cq_poll_info->inv_stag;
		break;
	case IRDMA_OP_TYPE_REC:
		entry->opcode = IBV_WC_RECV;
		break;
	case IRDMA_OP_TYPE_REC_IMM:
		entry->opcode = IBV_WC_RECV_RDMA_WITH_IMM;
		break;
	default:
		entry->opcode = IBV_WC_RECV;
		break;
	}

	entry->qp_num = cq_poll_info->qp_id;
	qp = cq_poll_info->qp_handle;
	ib_qp = qp->back_qp;

	if (ib_qp->qp_type == IBV_QPT_UD) {
		entry->src_qp = cq_poll_info->ud_src_qpn;
		entry->wc_flags |= IBV_WC_GRH;
	} else {
		entry->src_qp = cq_poll_info->qp_id;
	}
	entry->byte_len = cq_poll_info->bytes_xfered;
}

/**
 * irdma_get_cqes - get cq entries
 * @num_entries: requested number of entries
 * @cqe_count: received number of entries
 * @ukcq: cq to get completion entries from
 * @new_cqe: true, if at least one completion
 * @entry: wr of a completed entry
 */
static int irdma_get_cqes(struct irdma_cq_uk *ukcq, int num_entries,
			  int *cqe_count, bool *new_cqe, struct ibv_wc **entry)
{
	struct irdma_cq_poll_info cq_poll_info;

	while (*cqe_count < num_entries) {
		int ret = ukcq->ops.iw_cq_poll_cmpl(ukcq, &cq_poll_info);

		if (ret == IRDMA_ERR_Q_EMPTY) {
			break;
		} else if (ret == IRDMA_ERR_Q_DESTROYED) {
			*new_cqe = true;
			continue;
		} else if (ret) {
			if (!*cqe_count)
				*cqe_count = -1;
			return -EINVAL;
		}
		*new_cqe = true;
		irdma_process_cqe(*entry, &cq_poll_info);
		(*cqe_count)++;
		(*entry)++;
	}

	return 0;
}

/**
 * irdma_upoll_cq - user app to poll cq
 * @cq: cq to poll
 * @num_entries: max cq entries to poll
 * @entry: for each completion complete entry
 */
int irdma_upoll_cq(struct ibv_cq *cq, int num_entries, struct ibv_wc *entry)
{
	struct irdma_cq_buf *cq_buf, *next;
	struct irdma_cq_buf *last_buf = NULL;
	struct irdma_cq_uk *ukcq;
	struct irdma_ucq *iwucq;
	bool new_cqe = false;
	int resized_bufs = 0;
	int cqe_count = 0;
	int ret;

	iwucq = to_irdma_ucq(cq);
	ukcq = &iwucq->cq;

	ret = pthread_spin_lock(&iwucq->lock);
	if (ret)
		return ret;
	/* go through the list of previously resized CQ buffers */
	list_for_each_safe(&iwucq->resize_list, cq_buf, next, list) {
		bool last_cqe = false;

		ret = irdma_get_cqes(&cq_buf->cq, num_entries,
				     &cqe_count, &last_cqe, &entry);

		if (ret) {
			fprintf(stderr, PFX "%s: Error polling resized CQ, status %d\n",
				__func__, ret);
			goto exit;
		}
		/* save the resized CQ buffer which has received the last cqe */
		if (last_cqe)
			last_buf = cq_buf;
	}

	/* check the current CQ buffer for new cqes */
	ret = irdma_get_cqes(ukcq, num_entries, &cqe_count, &new_cqe, &entry);
	if (ret) {
		fprintf(stderr, PFX "%s: Error polling CQ, status %d\n",
			__func__, ret);
		goto exit;
	}

	if (new_cqe)
		/* all previous CQ resizes are complete */
		resized_bufs = irdma_process_resize_list(iwucq, NULL);
	else if (last_buf)
		/* only CQ resizes up to the last_buf are complete */
		resized_bufs = irdma_process_resize_list(iwucq, last_buf);
	if (resized_bufs)
		/* report to the HW the number of complete CQ resizes */
		iwucq->cq.ops.iw_cq_set_resized_cnt(&iwucq->cq, resized_bufs);
exit:
	pthread_spin_unlock(&iwucq->lock);

	return cqe_count;
}

/**
 * irdma_arm_cq - arm of cq
 * @iwucq: cq to which arm
 * @cq_notify: notification params
 */
static void irdma_arm_cq(struct irdma_ucq *iwucq,
			 enum irdma_cmpl_notify cq_notify)
{
	iwucq->is_armed = true;
	iwucq->arm_sol = true;
	iwucq->skip_arm = false;
	iwucq->skip_sol = true;

	iwucq->cq.ops.iw_cq_request_notification(&iwucq->cq, cq_notify);
}

/**
 * irdma_uarm_cq - callback for arm of cq
 * @cq: cq to arm
 * @solicited: to get notify params
 */
int irdma_uarm_cq(struct ibv_cq *cq, int solicited)
{
	struct irdma_ucq *iwucq;
	enum irdma_cmpl_notify cq_notify = IRDMA_CQ_COMPL_EVENT;
	int ret;

	iwucq = to_irdma_ucq(cq);
	if (solicited)
		cq_notify = IRDMA_CQ_COMPL_SOLICITED;

	ret = pthread_spin_lock(&iwucq->lock);
	if (ret)
		return ret;

	if (iwucq->is_armed) {
		if (iwucq->arm_sol && !solicited) {
			irdma_arm_cq(iwucq, cq_notify);
		} else {
			iwucq->skip_arm = true;
			iwucq->skip_sol = solicited ? true : false;
		}
	} else {
		irdma_arm_cq(iwucq, cq_notify);
	}

	pthread_spin_unlock(&iwucq->lock);

	return 0;
}

/**
 * irdma_cq_event - cq to do completion event
 * @cq: cq to arm
 */
void irdma_cq_event(struct ibv_cq *cq)
{
	struct irdma_ucq *iwucq;

	iwucq = to_irdma_ucq(cq);
	if (pthread_spin_lock(&iwucq->lock))
		return;

	if (iwucq->skip_arm)
		irdma_arm_cq(iwucq, IRDMA_CQ_COMPL_EVENT);
	else
		iwucq->is_armed = false;

	pthread_spin_unlock(&iwucq->lock);
}

/**
 * irdma_destroy_vmapped_qp - destroy resources for qp
 * @iwuqp: qp struct for resources
 * @sq_base: qp base ptr
 */
static int irdma_destroy_vmapped_qp(struct irdma_uqp *iwuqp,
				    struct irdma_qp_quanta *sq_base)
{
	int ret;

	ret = ibv_cmd_destroy_qp(&iwuqp->ibv_qp);
	if (ret)
		return ret;

	if (iwuqp->qp.push_db)
		munmap(iwuqp->qp.push_db, IRDMA_HW_PAGE_SIZE);
	if (iwuqp->qp.push_wqe)
		munmap(iwuqp->qp.push_wqe, IRDMA_HW_PAGE_SIZE);

	ibv_cmd_dereg_mr(&iwuqp->vmr);
	free((void *)sq_base);

	return 0;
}

/**
 * irdma_vmapped_qp - create resources for qp
 * @iwuqp: qp struct for resources
 * @pd: pd for the qp
 * @attr: attributes of qp passed
 * @resp: response back from create qp
 * @sqdepth: depth of sq
 * @rqdepth: depth of rq
 * @info: info for initializing user level qp
 * @abi_ver: abi version of the create qp command
 */
static int irdma_vmapped_qp(struct irdma_uqp *iwuqp, struct ibv_pd *pd,
			    struct ibv_qp_init_attr *attr, int sqdepth,
			    int rqdepth, struct irdma_qp_uk_init_info *info,
			    int abi_ver)
{
	struct irdma_ucreate_qp cmd = {};
	struct i40iw_ucreate_qp cmd_legacy = {};
	int sqsize, rqsize, totalqpsize;
	struct irdma_ucreate_qp_resp resp = {};
	struct i40iw_ucreate_qp_resp resp_legacy = {};
	struct irdma_ureg_mr reg_mr_cmd = {};
	struct ib_uverbs_reg_mr_resp reg_mr_resp = {};
	u32 sq_pages, rq_pages;
	int ret;

	sqsize = sqdepth * IRDMA_QP_WQE_MIN_SIZE;
	rqsize = rqdepth * IRDMA_QP_WQE_MIN_SIZE;

	sq_pages = irdma_num_of_pages(sqsize);
	rq_pages = irdma_num_of_pages(rqsize);
	sqsize = sq_pages << 12;
	rqsize = rq_pages << 12;
	totalqpsize = rqsize + sqsize + IRDMA_DB_SHADOW_AREA_SIZE;
	info->sq = memalign(IRDMA_HW_PAGE_SIZE, totalqpsize);

	if (!info->sq) {
		fprintf(stderr, PFX "%s: failed to allocate memory for SQ\n",
			__func__);
		return ENOMEM;
	}

	memset(info->sq, 0, totalqpsize);
	info->rq = &info->sq[sqsize / IRDMA_QP_WQE_MIN_SIZE];
	info->shadow_area = info->rq[rqsize / IRDMA_QP_WQE_MIN_SIZE].elem;

	reg_mr_cmd.reg_type = IW_MEMREG_TYPE_QP;
	reg_mr_cmd.sq_pages = sq_pages;
	reg_mr_cmd.rq_pages = rq_pages;

	ret = ibv_cmd_reg_mr(pd, (void *)info->sq, totalqpsize,
			     (uintptr_t)info->sq, IBV_ACCESS_LOCAL_WRITE,
			     &iwuqp->vmr, &reg_mr_cmd.ibv_cmd,
			     sizeof(reg_mr_cmd), &reg_mr_resp,
			     sizeof(reg_mr_resp));
	if (ret) {
		fprintf(stderr, PFX "%s: failed to pin memory for SQ\n",
			__func__);
		free(info->sq);
		return ret;
	}

	/* GEN_1 legacy support with i40iw */
	if (abi_ver <= 5) {
		cmd_legacy.user_wqe_bufs = (__u64)((uintptr_t)info->sq);
		cmd_legacy.user_compl_ctx = (__u64)(uintptr_t)&iwuqp->qp;
		ret = ibv_cmd_create_qp(pd, &iwuqp->ibv_qp, attr,
					&cmd_legacy.ibv_cmd, sizeof(cmd_legacy),
					&resp_legacy.ibv_resp,
					sizeof(struct i40iw_ucreate_qp_resp));
		if (ret)
			goto error;
		info->sq_size = resp_legacy.actual_sq_size;
		info->rq_size = resp_legacy.actual_rq_size;
		info->first_sq_wq = 1;
		info->qp_caps = 0;
		info->qp_id = resp_legacy.qp_id;
		iwuqp->irdma_drv_opt = resp_legacy.i40iw_drv_opt;
		iwuqp->ibv_qp.qp_num = resp_legacy.qp_id;
	} else {
		cmd.user_wqe_bufs = (__u64)((uintptr_t)info->sq);
		cmd.user_compl_ctx = (__u64)(uintptr_t)&iwuqp->qp;
		ret = ibv_cmd_create_qp(pd, &iwuqp->ibv_qp, attr, &cmd.ibv_cmd,
					sizeof(cmd), &resp.ibv_resp,
					sizeof(struct irdma_ucreate_qp_resp));
		if (ret)
			goto error;
		info->sq_size = resp.actual_sq_size;
		info->rq_size = resp.actual_rq_size;
		info->first_sq_wq = resp.lsmm;
		info->qp_caps = resp.qp_caps;
		info->qp_id = resp.qp_id;
		iwuqp->irdma_drv_opt = resp.irdma_drv_opt;
		iwuqp->ibv_qp.qp_num = resp.qp_id;
	}

	iwuqp->send_cq = to_irdma_ucq(attr->send_cq);
	iwuqp->recv_cq = to_irdma_ucq(attr->recv_cq);
	iwuqp->send_cq->uqp = iwuqp;
	iwuqp->recv_cq->uqp = iwuqp;

	return 0;
error:
	fprintf(stderr, PFX "%s: failed to create QP, status %d\n", __func__, ret);
	ibv_cmd_dereg_mr(&iwuqp->vmr);
	free(info->sq);
	return ret;
}

/**
 * irdma_ucreate_qp - create qp on user app
 * @pd: pd for the qp
 * @attr: attributes of the qp to be created (sizes, sge, cq)
 */
struct ibv_qp *irdma_ucreate_qp(struct ibv_pd *pd,
				struct ibv_qp_init_attr *attr)
{
	struct irdma_uvcontext *iwvctx = to_irdma_uctx(pd->context);
	struct irdma_uk_attrs *uk_attrs = &iwvctx->uk_attrs;
	struct irdma_qp_uk_init_info info = {};
	struct irdma_uqp *iwuqp;
	u32 sqdepth, rqdepth;
	u8 sqshift, rqshift;
	int status;

	if (attr->qp_type != IBV_QPT_RC && attr->qp_type != IBV_QPT_UD) {
		fprintf(stderr, PFX "%s: failed to create QP, unsupported QP type: 0x%x\n",
			__func__, attr->qp_type);
		return NULL;
	}

	if (attr->cap.max_send_sge > uk_attrs->max_hw_wq_frags ||
	    attr->cap.max_recv_sge > uk_attrs->max_hw_wq_frags ||
	    attr->cap.max_inline_data > uk_attrs->max_hw_inline) {
		fprintf(stderr, PFX "%s: invalid caps, max_send_sge=%d max_recv_sge=%d max_inline_data=%d\n",
			__func__, attr->cap.max_send_sge, attr->cap.max_recv_sge,
			attr->cap.max_inline_data);
		return NULL;
	}
	irdma_get_wqe_shift(uk_attrs,
			    uk_attrs->hw_rev > IRDMA_GEN_1 ? attr->cap.max_send_sge + 1 :
				attr->cap.max_send_sge,
			    attr->cap.max_inline_data, &sqshift);
	status = irdma_get_sqdepth(uk_attrs, attr->cap.max_send_wr, sqshift,
				   &sqdepth);
	if (status) {
		fprintf(stderr, PFX "%s: invalid SQ attributes, max_send_wr=%d max_send_sge=%d max_inline=%d\n",
			__func__, attr->cap.max_send_wr, attr->cap.max_send_sge,
			attr->cap.max_inline_data);
		return NULL;
	}

	if (uk_attrs->hw_rev == IRDMA_GEN_1 && iwvctx->abi_ver > 4)
		rqshift = IRDMA_MAX_RQ_WQE_SHIFT_GEN1;
	else
		irdma_get_wqe_shift(uk_attrs, attr->cap.max_recv_sge, 0,
				    &rqshift);

	status = irdma_get_rqdepth(uk_attrs, attr->cap.max_recv_wr, rqshift,
				   &rqdepth);
	if (status) {
		fprintf(stderr, PFX "%s: invalid RQ attributes, max_recv_wr=%d max_recv_sge=%d\n",
			__func__, attr->cap.max_recv_wr, attr->cap.max_recv_sge);
		return NULL;
	}

	iwuqp = memalign(1024, sizeof(*iwuqp));
	if (!iwuqp)
		return NULL;

	memset(iwuqp, 0, sizeof(*iwuqp));

	if (pthread_spin_init(&iwuqp->lock, PTHREAD_PROCESS_PRIVATE))
		goto err_free_qp;

	info.sq_size = sqdepth >> sqshift;
	info.rq_size = rqdepth >> rqshift;
	attr->cap.max_send_wr = info.sq_size;
	attr->cap.max_recv_wr = info.rq_size;

	info.uk_attrs = uk_attrs;
	info.max_sq_frag_cnt = attr->cap.max_send_sge;
	info.max_rq_frag_cnt = attr->cap.max_recv_sge;

	info.wqe_alloc_db = (u32 *)iwvctx->iwupd->db;
	info.sq_wrtrk_array = calloc(sqdepth, sizeof(*info.sq_wrtrk_array));
	info.abi_ver = iwvctx->abi_ver;
	if (!info.sq_wrtrk_array) {
		fprintf(stderr, PFX "%s: failed to allocate memory for SQ work array\n",
			__func__);
		goto err_destroy_lock;
	}

	info.rq_wrid_array = calloc(rqdepth, sizeof(*info.rq_wrid_array));
	if (!info.rq_wrid_array) {
		fprintf(stderr, PFX "%s: failed to allocate memory for RQ work array\n",
			__func__);
		goto err_free_sq_wrtrk;
	}

	iwuqp->sq_sig_all = attr->sq_sig_all;
	iwuqp->qp_type = attr->qp_type;
	status = irdma_vmapped_qp(iwuqp, pd, attr, sqdepth, rqdepth, &info,
				  iwvctx->abi_ver);
	if (status) {
		fprintf(stderr, PFX "%s: failed to map QP\n", __func__);
		goto err_free_rq_wrid;
	}

	iwuqp->qp.back_qp = iwuqp;
	info.max_sq_frag_cnt = attr->cap.max_send_sge;
	info.max_rq_frag_cnt = attr->cap.max_recv_sge;
	info.max_inline_data = attr->cap.max_inline_data;
	iwuqp->qp.force_fence = true;
	status = iwvctx->dev.ops_uk.iw_qp_uk_init(&iwuqp->qp, &info);
	if (!status) {
		attr->cap.max_send_wr = (sqdepth - IRDMA_SQ_RSVD) >> sqshift;
		attr->cap.max_recv_wr = (rqdepth - IRDMA_RQ_RSVD) >> rqshift;
		return &iwuqp->ibv_qp;
	}

	irdma_destroy_vmapped_qp(iwuqp, info.sq);
err_free_rq_wrid:
	free(info.rq_wrid_array);
err_free_sq_wrtrk:
	free(info.sq_wrtrk_array);
err_destroy_lock:
	pthread_spin_destroy(&iwuqp->lock);
err_free_qp:
	free(iwuqp);

	return NULL;
}

/**
 * irdma_uquery_qp - query qp for some attribute
 * @qp: qp for the attributes query
 * @attr: to return the attributes
 * @attr_mask: mask of what is query for
 * @init_attr: initial attributes during create_qp
 */
int irdma_uquery_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask,
		    struct ibv_qp_init_attr *init_attr)
{
	struct ibv_query_qp cmd;

	return ibv_cmd_query_qp(qp, attr, attr_mask, init_attr, &cmd,
				sizeof(cmd));
}

/**
 * irdma_umodify_qp - send qp modify to driver
 * @qp: qp to modify
 * @attr: attribute to modify
 * @attr_mask: mask of the attribute
 */
int irdma_umodify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask)
{
	struct irdma_umodify_qp_resp resp = {
		.push_idx = IRDMA_INVALID_PUSH_PAGE_INDEX,
		.push_offset = 0,
	};
	struct ibv_modify_qp cmd = {};
	struct ibv_modify_qp_ex cmd_ex = {};
	struct irdma_uqp *iwuqp = to_irdma_uqp(qp);
	struct irdma_uvcontext *iwctx = to_irdma_uctx(qp->context);

	if (iwctx->uk_attrs.hw_rev > IRDMA_GEN_1 && attr_mask & IBV_QP_STATE) {
		u64 offset;
		void *map;
		int ret;

		ret = ibv_cmd_modify_qp_ex(qp, attr, attr_mask, &cmd_ex,
					   sizeof(cmd_ex), &resp.ibv_resp, sizeof(resp));
		if (ret || resp.push_idx == IRDMA_INVALID_PUSH_PAGE_INDEX)
			return ret;

		offset = (resp.push_idx + IRDMA_BASE_PUSH_PAGE) * IRDMA_HW_PAGE_SIZE;
		map = mmap(NULL, IRDMA_HW_PAGE_SIZE, PROT_WRITE | PROT_READ,
			   MAP_SHARED, qp->context->cmd_fd, offset);
		if (map == MAP_FAILED) {
			fprintf(stderr, PFX "failed to map push page, errno %d\n", errno);
		} else {
			iwuqp->qp.push_wqe = map;

			offset += IRDMA_HW_PAGE_SIZE;
			map = mmap(NULL, IRDMA_HW_PAGE_SIZE,
				   PROT_WRITE | PROT_READ, MAP_SHARED,
				   qp->context->cmd_fd, offset);
			if (map == MAP_FAILED) {
				fprintf(stderr, PFX "failed to map push doorbell, errno %d\n",
					errno);
				munmap(iwuqp->qp.push_wqe, IRDMA_HW_PAGE_SIZE);
				iwuqp->qp.push_wqe = NULL;
			} else {
				iwuqp->qp.push_wqe += resp.push_offset;
				iwuqp->qp.push_db = map + resp.push_offset;
			}
		}

		return ret;
	} else {
		return ibv_cmd_modify_qp(qp, attr, attr_mask, &cmd, sizeof(cmd));
	}

}

/**
 * irdma_clean_cqes - clean cq entries for qp
 * @qp: qp for which completions are cleaned
 * @iwcq: cq to be cleaned
 */
static void irdma_clean_cqes(struct irdma_qp_uk *qp, struct irdma_ucq *iwucq)
{
	struct irdma_cq_uk *ukcq = &iwucq->cq;
	int ret;

	ret = pthread_spin_lock(&iwucq->lock);
	if (ret) {
		fprintf(stderr, "irdma: Unable to clean cqes\n");
		return;
	}
	ukcq->ops.iw_cq_clean((void *)qp, ukcq);
	pthread_spin_unlock(&iwucq->lock);
}

/**
 * irdma_udestroy_qp - destroy qp
 * @qp: qp to destroy
 */
int irdma_udestroy_qp(struct ibv_qp *qp)
{
	struct irdma_uqp *iwuqp = to_irdma_uqp(qp);
	int ret;

	ret = pthread_spin_destroy(&iwuqp->lock);
	if (ret)
		goto err;

	ret = irdma_destroy_vmapped_qp(iwuqp, iwuqp->qp.sq_base);
	if (ret)
		goto err;

	if (iwuqp->qp.sq_wrtrk_array)
		free(iwuqp->qp.sq_wrtrk_array);
	if (iwuqp->qp.rq_wrid_array)
		free(iwuqp->qp.rq_wrid_array);

	/* Clean any pending completions from the cq(s) */
	if (iwuqp->send_cq)
		irdma_clean_cqes(&iwuqp->qp, iwuqp->send_cq);

	if (iwuqp->recv_cq && iwuqp->recv_cq != iwuqp->send_cq)
		irdma_clean_cqes(&iwuqp->qp, iwuqp->recv_cq);

	free(iwuqp);
	return 0;

err:
	fprintf(stderr, PFX "%s: failed to destroy QP, status %d\n",
		__func__, ret);

	return ret;
}

/**
 * irdma_copy_sg_list - copy sg list for qp
 * @sg_list: copied into sg_list
 * @sgl: copy from sgl
 * @num_sges: count of sg entries
 * @max_sges: count of max supported sg entries
 */
static void irdma_copy_sg_list(struct irdma_sge *sg_list, struct ibv_sge *sgl,
			       int num_sges)
{
	int i;

	for (i = 0; i < num_sges; i++) {
		sg_list[i].tag_off = sgl[i].addr;
		sg_list[i].len = sgl[i].length;
		sg_list[i].stag = sgl[i].lkey;
	}
}

/**
 * irdma_post_send -  post send wr for user application
 * @ib_qp: qp to post wr
 * @ib_wr: work request ptr
 * @bad_wr: return of bad wr if err
 */
int irdma_upost_send(struct ibv_qp *ib_qp, struct ibv_send_wr *ib_wr,
		     struct ibv_send_wr **bad_wr)
{
	struct irdma_uqp *iwuqp;
	struct irdma_post_sq_info info;
	struct irdma_uvcontext *iwvctx = to_irdma_uctx(ib_qp->context);
	struct irdma_uk_attrs *uk_attrs = &iwvctx->uk_attrs;
	enum irdma_status_code ret = 0;
	bool inv_stag = false;
	int err = 0;

	iwuqp = (struct irdma_uqp *)ib_qp;

	err = pthread_spin_lock(&iwuqp->lock);
	if (err)
		return err;

	while (ib_wr) {
		memset(&info, 0, sizeof(info));
		info.wr_id = (u64)(ib_wr->wr_id);
		if ((ib_wr->send_flags & IBV_SEND_SIGNALED) ||
		    iwuqp->sq_sig_all)
			info.signaled = true;
		if (ib_wr->send_flags & IBV_SEND_FENCE)
			info.read_fence = true;

		switch (ib_wr->opcode) {
		case IBV_WR_SEND_WITH_IMM:
			if (iwuqp->qp.qp_caps & IRDMA_SEND_WITH_IMM) {
				info.imm_data_valid = true;
				info.imm_data = ntohl(ib_wr->imm_data);
			} else {
				err = EINVAL;
				break;
			}
			/* fall-through */
		case IBV_WR_SEND:
			/* fall-through */
		case IBV_WR_SEND_WITH_INV:
			if (ib_wr->opcode == IBV_WR_SEND ||
			    ib_wr->opcode == IBV_WR_SEND_WITH_IMM) {
				if (ib_wr->send_flags & IBV_SEND_SOLICITED)
					info.op_type = IRDMA_OP_TYPE_SEND_SOL;
				else
					info.op_type = IRDMA_OP_TYPE_SEND;
			} else {
				if (ib_wr->send_flags & IBV_SEND_SOLICITED)
					info.op_type = IRDMA_OP_TYPE_SEND_SOL_INV;
				else
					info.op_type = IRDMA_OP_TYPE_SEND_INV;
				info.stag_to_inv = ib_wr->invalidate_rkey;
			}
			if (ib_wr->send_flags & IBV_SEND_INLINE) {
				info.op.inline_send.data = (void *)(uintptr_t)ib_wr->sg_list[0].addr;
				info.op.inline_send.len = ib_wr->sg_list[0].length;
				if (ib_qp->qp_type == IBV_QPT_UD) {
					struct irdma_uah *ah  = to_irdma_uah(ib_wr->wr.ud.ah);

					info.op.inline_send.ah_id = ah->ah_id;
					info.op.inline_send.qkey = ib_wr->wr.ud.remote_qkey;
					info.op.inline_send.dest_qp = ib_wr->wr.ud.remote_qpn;
					ret = iwuqp->qp.qp_ops.iw_inline_send(&iwuqp->qp, &info, false);
				} else {
					ret = iwuqp->qp.qp_ops.iw_inline_send(
						&iwuqp->qp, &info, false);
				}
			} else {
				info.op.send.num_sges = ib_wr->num_sge;
				info.op.send.sg_list = (struct irdma_sge *)ib_wr->sg_list;
				if (ib_qp->qp_type == IBV_QPT_UD) {
					struct irdma_uah *ah  = to_irdma_uah(ib_wr->wr.ud.ah);

					info.op.inline_send.ah_id = ah->ah_id;
					info.op.inline_send.qkey = ib_wr->wr.ud.remote_qkey;
					info.op.inline_send.dest_qp = ib_wr->wr.ud.remote_qpn;
					ret = iwuqp->qp.qp_ops.iw_send(&iwuqp->qp, &info, false);
				} else {
					ret = iwuqp->qp.qp_ops.iw_send(
						&iwuqp->qp, &info, false);
				}
			}
			if (ret) {
				if (ret == IRDMA_ERR_QP_TOOMANY_WRS_POSTED)
					err = ENOMEM;
				else
					err = EINVAL;
			}
			break;
		case IBV_WR_RDMA_WRITE_WITH_IMM:
			if (iwuqp->qp.qp_caps & IRDMA_WRITE_WITH_IMM) {
				info.imm_data_valid = true;
				info.imm_data = ntohl(ib_wr->imm_data);
			} else {
				err = EINVAL;
				break;
			}
			/* fall-through */
		case IBV_WR_RDMA_WRITE:
			if (ib_wr->send_flags & IBV_SEND_SOLICITED)
				info.op_type = IRDMA_OP_TYPE_RDMA_WRITE_SOL;
			else
				info.op_type = IRDMA_OP_TYPE_RDMA_WRITE;

			if (ib_wr->send_flags & IBV_SEND_INLINE) {
				info.op.inline_rdma_write.data = (void *)(uintptr_t)ib_wr->sg_list[0].addr;
				info.op.inline_rdma_write.len = ib_wr->sg_list[0].length;
				info.op.inline_rdma_write.rem_addr.tag_off = ib_wr->wr.rdma.remote_addr;
				info.op.inline_rdma_write.rem_addr.stag = ib_wr->wr.rdma.rkey;
				ret = iwuqp->qp.qp_ops.iw_inline_rdma_write(&iwuqp->qp, &info, false);
			} else {
				info.op.rdma_write.lo_sg_list = (void *)ib_wr->sg_list;
				info.op.rdma_write.num_lo_sges = ib_wr->num_sge;
				info.op.rdma_write.rem_addr.tag_off = ib_wr->wr.rdma.remote_addr;
				info.op.rdma_write.rem_addr.stag = ib_wr->wr.rdma.rkey;
				ret = iwuqp->qp.qp_ops.iw_rdma_write(&iwuqp->qp, &info, false);
			}
			if (ret) {
				if (ret == IRDMA_ERR_QP_TOOMANY_WRS_POSTED)
					err = ENOMEM;
				else
					err = EINVAL;
			}
			break;
		case IBV_WR_RDMA_READ:
			if (ib_wr->num_sge > uk_attrs->max_hw_read_sges) {
				err = EINVAL;
				break;
			}
			info.op_type = IRDMA_OP_TYPE_RDMA_READ;
			info.op.rdma_read.rem_addr.tag_off = ib_wr->wr.rdma.remote_addr;
			info.op.rdma_read.rem_addr.stag = ib_wr->wr.rdma.rkey;

			info.op.rdma_read.lo_sg_list = (void *)ib_wr->sg_list;
			info.op.rdma_read.num_lo_sges = ib_wr->num_sge;
			ret = iwuqp->qp.qp_ops.iw_rdma_read(&iwuqp->qp, &info,
							    inv_stag, false);
			if (ret) {
				if (ret == IRDMA_ERR_QP_TOOMANY_WRS_POSTED)
					err = ENOMEM;
				else
					err = EINVAL;
			}
			break;
		case IBV_WR_BIND_MW:
			if (ib_qp->qp_type != IBV_QPT_RC) {
				err = EINVAL;
				break;
			}
			info.op_type = IRDMA_OP_TYPE_BIND_MW;
			if (ib_wr->bind_mw.bind_info.mw_access_flags &
			    IBV_ACCESS_ZERO_BASED)
				info.op.bind_window.addressing_type = IRDMA_ADDR_TYPE_ZERO_BASED;
			else
				info.op.bind_window.addressing_type = IRDMA_ADDR_TYPE_VA_BASED;
			info.op.bind_window.bind_len = ib_wr->bind_mw.bind_info.length;
			info.op.bind_window.ena_reads =
				(ib_wr->bind_mw.bind_info.mw_access_flags & IBV_ACCESS_REMOTE_READ) ? 1 : 0;
			info.op.bind_window.ena_writes =
				(ib_wr->bind_mw.bind_info.mw_access_flags & IBV_ACCESS_REMOTE_WRITE) ? 1 : 0;
			info.op.bind_window.mr_stag = ib_wr->bind_mw.bind_info.mr->rkey;
			info.op.bind_window.mw_stag = ib_wr->bind_mw.mw->rkey;
			info.op.bind_window.va =  (void *)(uintptr_t)ib_wr->bind_mw.bind_info.addr;
			ret = iwuqp->qp.qp_ops.iw_mw_bind(&iwuqp->qp, &info,
							  false);
			if (ret) {
				if (ret == IRDMA_ERR_QP_TOOMANY_WRS_POSTED)
					err = ENOMEM;
				else
					err = EINVAL;
			}
			break;
		default:
			/* error */
			err = EINVAL;
			fprintf(stderr, PFX "%s: post work request failed, invalid opcode: 0x%x\n",
				__func__, ib_wr->opcode);
			break;
		}
		if (err)
			break;

		ib_wr = ib_wr->next;
	}

	if (err)
		*bad_wr = ib_wr;
	iwuqp->qp.qp_ops.iw_qp_post_wr(&iwuqp->qp);

	pthread_spin_unlock(&iwuqp->lock);

	return err;
}

/**
 * irdma_post_recv - post receive wr for user application
 * @ib_wr: work request for receive
 * @bad_wr: bad wr caused an error
 */
int irdma_upost_recv(struct ibv_qp *ib_qp, struct ibv_recv_wr *ib_wr,
		     struct ibv_recv_wr **bad_wr)
{
	struct irdma_uqp *iwuqp = to_irdma_uqp(ib_qp);
	enum irdma_status_code ret = 0;
	struct irdma_post_rq_info post_recv = {};
	struct irdma_sge *sg_list;
	int err = 0;

	sg_list = malloc(sizeof(*sg_list) * iwuqp->qp.max_rq_frag_cnt);
	if (!sg_list)
		return ENOMEM;

	err = pthread_spin_lock(&iwuqp->lock);
	if (err) {
		free(sg_list);
		return err;
	}

	while (ib_wr) {
		if (ib_wr->num_sge > iwuqp->qp.max_rq_frag_cnt) {
			*bad_wr = ib_wr;
			err = EINVAL;
			goto error;
		}
		post_recv.num_sges = ib_wr->num_sge;
		post_recv.wr_id = ib_wr->wr_id;
		irdma_copy_sg_list(sg_list, ib_wr->sg_list, ib_wr->num_sge);
		post_recv.sg_list = sg_list;
		ret = iwuqp->qp.qp_ops.iw_post_receive(&iwuqp->qp, &post_recv);
		if (ret) {
			fprintf(stderr, PFX "%s: failed to post receives, status %d\n",
				__func__, ret);
			if (ret == IRDMA_ERR_QP_TOOMANY_WRS_POSTED)
				err = ENOMEM;
			else
				err = EINVAL;
			*bad_wr = ib_wr;
			goto error;
		}

		ib_wr = ib_wr->next;
	}
error:
	pthread_spin_unlock(&iwuqp->lock);
	free(sg_list);

	return err;
}

/**
 * irdma_async_event - handle async events from driver
 * @event: event received
 */
void irdma_async_event(struct ibv_context *context, struct ibv_async_event *event)
{
	struct irdma_uqp *iwuqp;

	switch (event->event_type) {
	case IBV_EVENT_QP_FATAL:
	case IBV_EVENT_QP_ACCESS_ERR:
		iwuqp = to_irdma_uqp(event->element.qp);
		iwuqp->qperr = 1;
		break;
	default:
		break;
	}
}

/**
 * irdma_ucreate_ah - create address handle associated with a pd
 * @ibpd: pd for the address handle
 * @attr: attributes of address handle
 */
struct ibv_ah *irdma_ucreate_ah(struct ibv_pd *ibpd, struct ibv_ah_attr *attr)
{
	struct irdma_uah *ah;
	union ibv_gid sgid;
	struct irdma_ucreate_ah_resp resp;
	int err;

	err = ibv_query_gid(ibpd->context, attr->port_num, attr->grh.sgid_index,
			    &sgid);
	if (err) {
		fprintf(stderr, "irdma: Error from ibv_query_gid.\n");
		return NULL;
	}

	ah = calloc(1, sizeof(*ah));
	if (!ah)
		return NULL;

	if (ibv_cmd_create_ah(ibpd, &ah->ibv_ah, attr, &resp.ibv_resp,
			      sizeof(resp))) {
		free(ah);
		return NULL;
	}

	ah->ah_id = resp.ah_id;

	return &ah->ibv_ah;
}

/**
 * irdma_udestroy_ah - destroy the address handle
 * @ibah: address handle
 */
int irdma_udestroy_ah(struct ibv_ah *ibah)
{
	struct irdma_uah *ah;
	int ret;

	ah = to_irdma_uah(ibah);

	ret = ibv_cmd_destroy_ah(ibah);
	if (ret)
		return ret;

	free(ah);

	return 0;
}

/**
 * irdma_uattach_mcast - Attach qp to multicast group implemented
 * @qp: The queue pair
 * @gid:The Global ID for multicast group
 * @lid: The Local ID
 */
int irdma_uattach_mcast(struct ibv_qp *qp, const union ibv_gid *gid,
			uint16_t lid)
{
	return ibv_cmd_attach_mcast(qp, gid, lid);
}

/**
 * irdma_udetach_mcast - Detach qp from multicast group
 * @qp: The queue pair
 * @gid:The Global ID for multicast group
 * @lid: The Local ID
 */
int irdma_udetach_mcast(struct ibv_qp *qp, const union ibv_gid *gid,
			uint16_t lid)
{
	return ibv_cmd_detach_mcast(qp, gid, lid);
}

/**
 * irdma_uresize_cq - resizes a cq
 * @cq: cq to resize
 * @cqe: the number of cqes of the new cq
 */
int irdma_uresize_cq(struct ibv_cq *cq, int cqe)
{
	struct irdma_uvcontext *iwvctx;
	struct irdma_uk_attrs *uk_attrs;
	struct irdma_uresize_cq cmd = {};
	struct ib_uverbs_resize_cq_resp resp = {};
	struct irdma_ureg_mr reg_mr_cmd = {};
	struct ib_uverbs_reg_mr_resp reg_mr_resp = {};
	struct irdma_ucq *iwucq = to_irdma_ucq(cq);
	struct irdma_cq_buf *cq_buf = NULL;
	struct irdma_cqe *cq_base = NULL;
	struct verbs_mr new_mr = {};
	u32 cq_size;
	u32 cq_pages;
	int ret = 0;

	iwvctx = to_irdma_uctx(cq->context);
	uk_attrs = &iwvctx->uk_attrs;

	if (!(uk_attrs->feature_flags & IRDMA_FEATURE_CQ_RESIZE))
		return ENOSYS;

	if (cqe > IRDMA_MAX_CQ_SIZE)
		return EINVAL;
	cqe++;
	if (uk_attrs->hw_rev > IRDMA_GEN_1)
		cqe *= 2;

	if (cqe < IRDMA_U_MINCQ_SIZE)
		cqe = IRDMA_U_MINCQ_SIZE;

	if (cqe == iwucq->cq.cq_size)
		return 0;

	cq_pages = irdma_num_of_pages(cqe * sizeof(struct irdma_cqe));
	cq_size = (cq_pages << 12);
	cq_base = memalign(IRDMA_HW_PAGE_SIZE, cq_size);
	if (!cq_base)
		goto err;

	memset(cq_base, 0, cq_size);

	cq_buf = malloc(sizeof(*cq_buf));
	if (!cq_buf)
		goto err;

	new_mr.ibv_mr.pd = iwucq->vmr.ibv_mr.pd;
	reg_mr_cmd.reg_type = IW_MEMREG_TYPE_CQ;
	reg_mr_cmd.cq_pages = cq_pages;

	ret = ibv_cmd_reg_mr(new_mr.ibv_mr.pd, (void *)cq_base, cq_size,
			     (uintptr_t)cq_base, IBV_ACCESS_LOCAL_WRITE,
			     &new_mr, &reg_mr_cmd.ibv_cmd, sizeof(reg_mr_cmd),
			     &reg_mr_resp, sizeof(reg_mr_resp));
	if (ret) {
		fprintf(stderr, "failed to pin memory for CQ\n");
		goto err;
	}

	ret = pthread_spin_lock(&iwucq->lock);
	if (ret) {
		ibv_cmd_dereg_mr(&new_mr);
		goto err;
	}
	cmd.user_cq_buffer = (__u64)((uintptr_t)cq_base);
	ret = ibv_cmd_resize_cq(&iwucq->ibv_cq, cqe, &cmd.ibv_cmd, sizeof(cmd),
				&resp, sizeof(resp));
	if (ret) {
		pthread_spin_unlock(&iwucq->lock);
		ibv_cmd_dereg_mr(&new_mr);
		fprintf(stderr, "failed to resize CQ ret = %d\n", ret);
		goto err;
	}

	memcpy(&cq_buf->cq, &iwucq->cq, sizeof(cq_buf->cq));
	cq_buf->vmr = iwucq->vmr;
	iwucq->vmr = new_mr;
	iwucq->cq.ops.iw_cq_resize(&iwucq->cq, (void *)cq_base,
				   iwucq->ibv_cq.cqe);
	list_add_tail(&iwucq->resize_list, &cq_buf->list);

	pthread_spin_unlock(&iwucq->lock);

	return ret;
err:
	if (cq_buf)
		free(cq_buf);
	if (cq_base)
		free(cq_base);
	return ret;
}
