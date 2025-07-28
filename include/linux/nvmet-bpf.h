/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2025 Hannes Reinecke, SUSE Software Solutions
 */

#ifndef _NVMET_BPF_H
#define _NVMET_BPF_H

struct nvmet_subsys;
struct nvmet_req;
struct nvmet_port;

/**
 * struct nvmet_bpf_ops - A BPF struct_ops of callbacks to allow
 *                        overwriting or adding new log pages
 *
 * @uuid: ops uuid
 * @subsysnqn: The subsystem NQN to attach to
 * @portid: The port id from which @subsysnqn can be reached
 * @log_page_supported: callback to check log page @lid is supported
 * @get_log_page: callback to complete the log page request
 */
struct nvmet_bpf_ops {
	/* UUID to distinguish different instances */
	uuid_t uuid;

	/* Subsystem NQN */
	char subsysnqn[256];

	/* Port ID */
	int portid;

	/* Test if a log page is supported */
	bool (*log_page_supported)(struct nvmet_bpf_ops *, u8 lid);

	/* Complete the get log page request */
	void (*get_log_page)(struct nvmet_bpf_ops *, struct nvmet_req *);

	/* private: don't show in doc, must be the last field */
	struct nvmet_subsys_link *subsys_link;
};

u64 nvmet_bpf_get_log_page_offset(struct nvmet_req *req);
u64 nvmet_bpf_get_log_page_len(struct nvmet_req *req);
bool nvmet_bpf_check_log_page_len(struct nvmet_req *req);
u8 nvmet_bpf_get_log_page_lid(struct nvmet_req *req);
u16 nvmet_bpf_copy_to_sgl(struct nvmet_req *req, off_t off,
			  const void *buf, size_t len);

#endif

