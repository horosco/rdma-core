# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved.
from pyverbs.base cimport PyverbsObject, PyverbsCM
cimport pyverbs.libibverbs as v

cdef class QPCap(PyverbsObject):
    cdef v.ibv_qp_cap cap

cdef class QPInitAttr(PyverbsObject):
    cdef v.ibv_qp_init_attr attr
    cdef object scq
    cdef object rcq

cdef class QPInitAttrEx(PyverbsObject):
    cdef v.ibv_qp_init_attr_ex attr
    cdef object scq
    cdef object rcq
    cdef object pd

cdef class QPAttr(PyverbsObject):
    cdef v.ibv_qp_attr attr

cdef class QP(PyverbsCM):
    cdef v.ibv_qp *qp
    cdef int type
    cdef int state
    cdef object pd
    cdef object context
    cpdef close(self)
    cdef update_cqs(self, init_attr)
    cdef object scq
    cdef object rcq
