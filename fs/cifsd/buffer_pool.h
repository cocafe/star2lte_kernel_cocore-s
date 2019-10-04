// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#ifndef __CIFSD_BUFFER_POOL_H__
#define __CIFSD_BUFFER_POOL_H__

struct cifsd_work;

void *cifsd_alloc(size_t size);
void cifsd_free(void *ptr);

void cifsd_free_request(void *addr);
void *cifsd_alloc_request(size_t size);
void cifsd_free_response(void *buffer);
void *cifsd_alloc_response(size_t size);

void *cifsd_realloc_response(void *ptr, size_t old_sz, size_t new_sz);

struct cifsd_work *cifsd_alloc_work_struct(void);
void cifsd_free_work_struct(struct cifsd_work *work);

void cifsd_free_file_struct(void *filp);
void *cifsd_alloc_file_struct(void);

void cifsd_destroy_buffer_pools(void);
int cifsd_init_buffer_pools(void);

#endif /* __CIFSD_BUFFER_POOL_H__ */
