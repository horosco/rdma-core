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

#ifndef IRDMA_STATUS_H
#define IRDMA_STATUS_H

/* Error Codes */
enum irdma_status_code {
	IRDMA_SUCCESS				= 0,
	IRDMA_ERR_NVM				= -1,
	IRDMA_ERR_NVM_CHECKSUM			= -2,
	IRDMA_ERR_CFG				= -4,
	IRDMA_ERR_PARAM				= -5,
	IRDMA_ERR_DEVICE_NOT_SUPPORTED		= -6,
	IRDMA_ERR_RESET_FAILED			= -7,
	IRDMA_ERR_SWFW_SYNC			= -8,
	IRDMA_ERR_NO_MEMORY			= -9,
	IRDMA_ERR_BAD_PTR			= -10,
	IRDMA_ERR_INVALID_PD_ID			= -11,
	IRDMA_ERR_INVALID_QP_ID			= -12,
	IRDMA_ERR_INVALID_CQ_ID			= -13,
	IRDMA_ERR_INVALID_CEQ_ID		= -14,
	IRDMA_ERR_INVALID_AEQ_ID		= -15,
	IRDMA_ERR_INVALID_SIZE			= -16,
	IRDMA_ERR_INVALID_ARP_INDEX		= -17,
	IRDMA_ERR_INVALID_FPM_FUNC_ID		= -18,
	IRDMA_ERR_QP_INVALID_MSG_SIZE		= -19,
	IRDMA_ERR_QP_TOOMANY_WRS_POSTED		= -20,
	IRDMA_ERR_INVALID_FRAG_COUNT		= -21,
	IRDMA_ERR_Q_EMPTY			= -22,
	IRDMA_ERR_INVALID_ALIGNMENT		= -23,
	IRDMA_ERR_FLUSHED_Q			= -24,
	IRDMA_ERR_INVALID_PUSH_PAGE_INDEX	= -25,
	IRDMA_ERR_INVALID_INLINE_DATA_SIZE	= -26,
	IRDMA_ERR_TIMEOUT			= -27,
	IRDMA_ERR_OPCODE_MISMATCH		= -28,
	IRDMA_ERR_CQP_COMPL_ERROR		= -29,
	IRDMA_ERR_INVALID_VF_ID			= -30,
	IRDMA_ERR_INVALID_HMCFN_ID		= -31,
	IRDMA_ERR_BACKING_PAGE_ERROR		= -32,
	IRDMA_ERR_NO_PBLCHUNKS_AVAILABLE	= -33,
	IRDMA_ERR_INVALID_PBLE_INDEX		= -34,
	IRDMA_ERR_INVALID_SD_INDEX		= -35,
	IRDMA_ERR_INVALID_PAGE_DESC_INDEX	= -36,
	IRDMA_ERR_INVALID_SD_TYPE		= -37,
	IRDMA_ERR_MEMCPY_FAILED			= -38,
	IRDMA_ERR_INVALID_HMC_OBJ_INDEX		= -39,
	IRDMA_ERR_INVALID_HMC_OBJ_COUNT		= -40,
	IRDMA_ERR_BUF_TOO_SHORT			= -43,
	IRDMA_ERR_BAD_IWARP_CQE			= -44,
	IRDMA_ERR_NVM_BLANK_MODE		= -45,
	IRDMA_ERR_NOT_IMPL			= -46,
	IRDMA_ERR_PE_DOORBELL_NOT_ENA		= -47,
	IRDMA_ERR_NOT_READY			= -48,
	IRDMA_NOT_SUPPORTED			= -49,
	IRDMA_ERR_FIRMWARE_API_VER		= -50,
	IRDMA_ERR_RING_FULL			= -51,
	IRDMA_ERR_MPA_CRC			= -61,
	IRDMA_ERR_NO_TXBUFS			= -62,
	IRDMA_ERR_SEQ_NUM			= -63,
	IRDMA_ERR_LIST_EMPTY			= -64,
	IRDMA_ERR_INVALID_MAC_ADDR		= -65,
	IRDMA_ERR_BAD_STAG			= -66,
	IRDMA_ERR_CQ_COMPL_ERROR		= -67,
	IRDMA_ERR_Q_DESTROYED			= -68,
	IRDMA_ERR_INVALID_FEAT_CNT		= -69,
	IRDMA_ERR_REG_CQ_FULL			= -70,
	IRDMA_ERR_VF_MSG_ERROR			= -71,
};
#endif /* IRDMA_STATUS_H */
