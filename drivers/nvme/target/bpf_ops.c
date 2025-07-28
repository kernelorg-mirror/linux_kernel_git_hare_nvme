// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Hannes Reinecke, SUSE */

#include <linux/bpf_verifier.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/nvmet-bpf.h>
#include "nvmet.h"
#include "bpf.h"

static struct btf *nvmet_bpf_ops_btf;
static char nvmet_bpf_ops_name[] = "nvmet_bpf_ops";

static int nvmet_bpf_ops_init(struct btf *btf)
{
	nvmet_bpf_ops_btf = btf;
	return 0;
}

static bool nvmet_bpf_ops_is_valid_access(int off, int size,
					  enum bpf_access_type type,
					  const struct bpf_prog *prog,
					  struct bpf_insn_access_aux *info)
{
	return bpf_tracing_btf_ctx_access(off, size, type, prog, info);
}

BTF_ID_LIST(nvmet_bpf_ops_args_ids)
BTF_ID(struct, nvmet_bpf_ops)
BTF_ID(struct, nvmet_subsys)
BTF_ID(struct, nvmet_req)

static int nvmet_bpf_ops_btf_struct_access(struct bpf_verifier_log *log,
					  const struct bpf_reg_state *reg,
					  int off, int size)
{
	if (!size)
		return NOT_INIT;

	bpf_log(log, "write access at off %d with size %d\n",
		off, size);
	return -EACCES;
}

static const struct bpf_verifier_ops nvmet_bpf_verifier_ops = {
	.get_func_proto = bpf_base_func_proto,
	.is_valid_access = nvmet_bpf_ops_is_valid_access,
	.btf_struct_access = nvmet_bpf_ops_btf_struct_access,
};

static int nvmet_bpf_ops_check_member(const struct btf_type *t,
				     const struct btf_member *member,
				     const struct bpf_prog *prog)
{
	u32 moff = __btf_member_bit_offset(t, member) / 8;

	switch (moff) {
	case offsetof(struct nvmet_bpf_ops, log_page_supported):
		break;
	case offsetof(struct nvmet_bpf_ops, get_log_page):
		break;
	default:
		if (prog->sleepable)
			return -EINVAL;
	}

	return 0;
}

static int nvmet_bpf_ops_init_member(const struct btf_type *t,
				    const struct btf_member *member,
				    void *kdata, const void *udata)
{
	const struct nvmet_bpf_ops *uops;
	struct nvmet_bpf_ops *kops;
	u32 moff;

	uops = (const struct nvmet_bpf_ops *)udata;
	kops = (struct nvmet_bpf_ops *)kdata;

	moff = __btf_member_bit_offset(t, member) / 8;

	switch (moff) {
	case offsetof(struct nvmet_bpf_ops, subsysnqn):
		memcpy(kops->subsysnqn, uops->subsysnqn,
		       sizeof(kops->subsysnqn));
		return 1;
	case offsetof(struct nvmet_bpf_ops, uuid):
		if (uuid_is_null(&uops->uuid))
			uuid_gen(&kops->uuid);
		else
			uuid_copy(&kops->uuid, &uops->uuid);
		return 1;
	}
	return 0;
}

static int nvmet_bpf_reg(void *kdata, struct bpf_link *link)
{
	struct nvmet_bpf_ops *ops = kdata;
	struct nvmet_port *p, *port = NULL;
	struct nvmet_subsys_link *s;

	pr_debug("%s: register %s port id %d\n",
		 __func__, ops->subsysnqn, ops->portid);

	list_for_each_entry(p, nvmet_ports, global_entry) {
		if (p->disc_addr.portid == ops->portid) {
			port = p;
			break;
		}
	}
	if (!port)
		return -EINVAL;

	down_write(&nvmet_config_sem);
	list_for_each_entry(s, &port->subsystems, entry) {
		if (!strncmp(s->subsys->subsysnqn, ops->subsysnqn,
			     NVMF_NQN_SIZE)) {
			s->bpf_ops = ops;
			ops->subsys_link = s;
			break;
		}
	}
	up_write(&nvmet_config_sem);
	if (ops->subsys_link) {
		pr_debug("%s: attached %pUb to %s\n",
			 __func__, &ops->uuid,
			 ops->subsys_link->subsys->serial);
		/* Raise a discovery log page changed AEN if log page is present */
		if (ops->log_page_supported(ops, NVME_LOG_DISC))
			nvmet_port_disc_changed(port, ops->subsys_link->subsys);
	}
	return ops->subsys_link ? 0 : -EINVAL;
}

static void nvmet_bpf_unreg(void *kdata, struct bpf_link *link)
{
	struct nvmet_bpf_ops *ops = kdata;
	struct nvmet_subsys_link *s = NULL;

	if (ops->subsys_link) {
		down_write(&nvmet_config_sem);
		s = ops->subsys_link;
		ops->subsys_link = NULL;
		s->bpf_ops = NULL;
		pr_debug("%s: unregistered %pUb from %s\n",
			 __func__, &ops->uuid, s->subsys->serial);
		up_write(&nvmet_config_sem);
	}
}

void nvmet_bpf_detach(struct nvmet_subsys_link *s)
{
	struct nvmet_bpf_ops *ops = s->bpf_ops;

	if (ops) {
		s->bpf_ops = NULL;
		ops->subsys_link = NULL;
	}
}

static bool __nvmet_bpf_log_page_supported(struct nvmet_bpf_ops *ops, u8 lid)
{
	return false;
}

static void __nvmet_bpf_get_log_page(struct nvmet_bpf_ops *ops, struct nvmet_req *req)
{
	nvmet_req_complete(req, NVME_SC_INVALID_FIELD | NVME_STATUS_DNR);
}

static struct nvmet_bpf_ops __bpf_nvmet_bpf_ops = {
	.uuid = {},
	.subsysnqn = {},
	.portid = -1,
	.log_page_supported = __nvmet_bpf_log_page_supported,
	.get_log_page = __nvmet_bpf_get_log_page,
	.subsys_link = NULL,
};

bool nvmet_bpf_supported(struct nvmet_subsys *subsys, struct nvmet_port *port)
{
	struct nvmet_subsys_link *s;
	struct nvmet_bpf_ops *ops = NULL;;

	down_read(&nvmet_config_sem);
	list_for_each_entry(s, &port->subsystems, entry) {
		if (s->subsys == subsys && s->bpf_ops) {
			ops = s->bpf_ops;
			break;
		}
	}
	up_read(&nvmet_config_sem);
	return !!ops;
}

bool nvmet_bpf_log_page_supported(struct nvmet_req *req, u8 lid)
{
	struct nvmet_subsys *subsys = req->sq->ctrl->subsys;
	struct nvmet_port *port = req->port;
	struct nvmet_subsys_link *s;
	struct nvmet_bpf_ops *ops = NULL;;

	down_read(&nvmet_config_sem);
	list_for_each_entry(s, &port->subsystems, entry) {
		if (s->subsys == subsys && s->bpf_ops) {
			ops = s->bpf_ops;
			break;
		}
	}
	up_read(&nvmet_config_sem);
	if (ops)
		return ops->log_page_supported(ops, lid);
	return false;
}

void nvmet_bpf_get_log_page(struct nvmet_subsys *subsys, struct nvmet_req *req)
{
	struct nvmet_port *port = req->port;
	struct nvmet_subsys_link *s;
	struct nvmet_bpf_ops *ops = NULL;;

	down_read(&nvmet_config_sem);
	list_for_each_entry(s, &port->subsystems, entry) {
		if (s->subsys == subsys && s->bpf_ops) {
			ops = s->bpf_ops;
			break;
		}
	}
	up_read(&nvmet_config_sem);
	if (ops)
		return ops->get_log_page(ops, req);

	req->error_loc = offsetof(struct nvme_get_log_page_command, lid);
	nvmet_req_complete(req, NVME_SC_INVALID_FIELD | NVME_STATUS_DNR);
}

__bpf_kfunc_start_defs();

__bpf_kfunc u64 nvmet_bpf_get_log_page_offset(struct nvmet_req *req)
{
	return nvmet_get_log_page_offset(req->cmd);
}
EXPORT_SYMBOL_GPL(nvmet_bpf_get_log_page_offset);

__bpf_kfunc u64 nvmet_bpf_get_log_page_len(struct nvmet_req *req)
{
	return nvmet_get_log_page_len(req->cmd);
}
EXPORT_SYMBOL_GPL(nvmet_bpf_get_log_page_len);

__bpf_kfunc bool nvmet_bpf_check_log_page_len(struct nvmet_req *req)
{
	return nvmet_check_transfer_len(req, nvmet_get_log_page_len(req->cmd));
}
EXPORT_SYMBOL_GPL(nvmet_bpf_check_log_page_len);

__bpf_kfunc u8 nvmet_bpf_get_log_page_lid(struct nvmet_req *req)
{
	return req->cmd->get_log_page.lid;
}
EXPORT_SYMBOL_GPL(nvmet_bpf_get_log_page_lid);

__bpf_kfunc u16 nvmet_bpf_copy_to_sgl(struct nvmet_req *req, off_t off,
				      const void *buf, size_t len)
{
	return nvmet_copy_to_sgl(req, off, buf, len);
}
EXPORT_SYMBOL_GPL(nvmet_bpf_copy_to_sgl);

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(nvmet_bpf_kfunc_set_ids)
BTF_ID_FLAGS(func, nvmet_bpf_get_log_page_offset)
BTF_ID_FLAGS(func, nvmet_bpf_get_log_page_len)
BTF_ID_FLAGS(func, nvmet_bpf_check_log_page_len)
BTF_ID_FLAGS(func, nvmet_bpf_get_log_page_lid)
BTF_ID_FLAGS(func, nvmet_bpf_copy_to_sgl)
BTF_KFUNCS_END(nvmet_bpf_kfunc_set_ids)

static const struct btf_kfunc_id_set nvmet_bpf_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &nvmet_bpf_kfunc_set_ids,
};

static struct bpf_struct_ops bpf_nvmet_bpf_ops = {
	.verifier_ops = &nvmet_bpf_verifier_ops,
	.init = nvmet_bpf_ops_init,
	.check_member = nvmet_bpf_ops_check_member,
	.init_member = nvmet_bpf_ops_init_member,
	.reg = nvmet_bpf_reg,
	.unreg = nvmet_bpf_unreg,
	.name = nvmet_bpf_ops_name,
	.cfi_stubs = &__bpf_nvmet_bpf_ops,
	.owner = THIS_MODULE,
};

int __init nvmet_bpf_struct_ops_init(void)
{
	int ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					&nvmet_bpf_kfunc_set);
	if (ret) {
		pr_err("Failed to register nvmet_bpf_kfunc_set, error %d\n", ret);
		return ret;
	}
	ret = register_bpf_struct_ops(&bpf_nvmet_bpf_ops, nvmet_bpf_ops);
	if (ret)
		pr_err("Failed to register nvmet_bpf_ops, error %d\n", ret);
	else
		pr_info("nvmet_bpf_ops registered\n");
	return ret;
}
