// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef NVMET_INT_BPF_HEADER
#define NVMET_INT_BPF_HEADER

#ifdef CONFIG_NVME_TARGET_BPF
#include <linux/filter.h>
#include <linux/nvmet-bpf.h>

void nvmet_bpf_detach(struct nvmet_subsys_link *s);
bool nvmet_bpf_supported(struct nvmet_subsys *subsys, struct nvmet_port *port);
bool nvmet_bpf_log_page_supported(struct nvmet_req *req, u8 lid);
void nvmet_bpf_get_log_page(struct nvmet_subsys *subsys, struct nvmet_req *req);
int __init nvmet_bpf_struct_ops_init(void);
#else
static inline void nvmet_bpf_detach(struct nvmet_subsys_link *s) {}
static inline bool nvmet_bpf_supported(struct nvmet_subsys *subsys, struct nvmet_port *port)
{
	return false;
}
static inline bool nvmet_bpf_log_page_supported(struct nvmet_req *req, u8 lid)
{
	return false;
}
static inline void nvmet_bpf_get_log_page(struct nvmet_subsys *subsys, struct nvmet_req *req)
{
	return nvmet_bpf_req_complete(req, NVME_SC_INVALID_FIELD | NVME_SC_DNR);
}
#endif
#endif
