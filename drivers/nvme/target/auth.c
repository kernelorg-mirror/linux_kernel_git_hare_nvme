// SPDX-License-Identifier: GPL-2.0
/*
 * NVMe over Fabrics DH-HMAC-CHAP authentication.
 * Copyright (c) 2020 Hannes Reinecke, SUSE Software Solutions.
 * All rights reserved.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/crc32.h>
#include <linux/base64.h>
#include <linux/ctype.h>
#include <linux/random.h>
#include <linux/nvme-auth.h>
#include <linux/nvme-keyring.h>
#include <linux/unaligned.h>

#include "nvmet.h"

void nvmet_auth_revoke_key(struct nvmet_host *host, bool set_ctrl)
{
	struct key *key = NULL;

	if (set_ctrl) {
		if (host->dhchap_ctrl_key) {
			key = host->dhchap_ctrl_key;
			host->dhchap_ctrl_key = NULL;
		}
	} else {
		if (host->dhchap_key) {
			key = host->dhchap_key;
			host->dhchap_key = NULL;
		}
	}
	if (key) {
		pr_debug("%s: revoke %s key %08x\n",
			 __func__, set_ctrl ? "ctrl" : "host",
			 key_serial(key));
		key_revoke(key);
		key_put(key);
	}
}

int nvmet_auth_set_key(struct nvmet_host *host, const char *secret,
		       bool set_ctrl)
{
	struct key *key;
	size_t len;

	if (!strlen(secret)) {
		nvmet_auth_revoke_key(host, set_ctrl);
		return 0;
	}

	len = strcspn(secret, "\n");
	key = nvme_auth_extract_key(NULL, secret, len);
	if (IS_ERR(key)) {
		pr_debug("%s: invalid key specification\n", __func__);
		return PTR_ERR(key);
	}
	down_read(&key->sem);
	if (key_validate(key)) {
		pr_warn("%s: key %08x invalidated\n",
			__func__, key_serial(key));
		up_read(&key->sem);
		key_put(key);
		return -EKEYREVOKED;
	}
	up_read(&key->sem);
	nvmet_auth_revoke_key(host, set_ctrl);
	if (set_ctrl)
		host->dhchap_ctrl_key = key;
	else
		host->dhchap_key = key;
	return 0;
}

int nvmet_setup_dhgroup(struct nvmet_ctrl *ctrl, u8 dhgroup_id)
{
	const char *dhgroup_kpp;
	int ret = 0;

	pr_debug("%s: ctrl %d selecting dhgroup %d\n",
		 __func__, ctrl->cntlid, dhgroup_id);

	if (ctrl->dh_tfm) {
		if (ctrl->dh_gid == dhgroup_id) {
			pr_debug("%s: ctrl %d reuse existing DH group %d\n",
				 __func__, ctrl->cntlid, dhgroup_id);
			return 0;
		}
		crypto_free_kpp(ctrl->dh_tfm);
		ctrl->dh_tfm = NULL;
		ctrl->dh_gid = 0;
	}

	if (dhgroup_id == NVME_AUTH_DHGROUP_NULL)
		return 0;

	dhgroup_kpp = nvme_auth_dhgroup_kpp(dhgroup_id);
	if (!dhgroup_kpp) {
		pr_debug("%s: ctrl %d invalid DH group %d\n",
			 __func__, ctrl->cntlid, dhgroup_id);
		return -EINVAL;
	}
	ctrl->dh_tfm = crypto_alloc_kpp(dhgroup_kpp, 0, 0);
	if (IS_ERR(ctrl->dh_tfm)) {
		pr_debug("%s: ctrl %d failed to setup DH group %d, err %ld\n",
			 __func__, ctrl->cntlid, dhgroup_id,
			 PTR_ERR(ctrl->dh_tfm));
		ret = PTR_ERR(ctrl->dh_tfm);
		ctrl->dh_tfm = NULL;
		ctrl->dh_gid = 0;
	} else {
		ctrl->dh_gid = dhgroup_id;
		pr_debug("%s: ctrl %d setup DH group %d\n",
			 __func__, ctrl->cntlid, ctrl->dh_gid);
		ret = nvme_auth_gen_privkey(ctrl->dh_tfm, ctrl->dh_gid);
		if (ret < 0) {
			pr_debug("%s: ctrl %d failed to generate private key, err %d\n",
				 __func__, ctrl->cntlid, ret);
			kfree_sensitive(ctrl->dh_key);
			ctrl->dh_key = NULL;
			return ret;
		}
		ctrl->dh_keysize = crypto_kpp_maxsize(ctrl->dh_tfm);
		kfree_sensitive(ctrl->dh_key);
		ctrl->dh_key = kzalloc(ctrl->dh_keysize, GFP_KERNEL);
		if (!ctrl->dh_key) {
			pr_warn("ctrl %d failed to allocate public key\n",
				ctrl->cntlid);
			return -ENOMEM;
		}
		ret = nvme_auth_gen_pubkey(ctrl->dh_tfm, ctrl->dh_key,
					   ctrl->dh_keysize);
		if (ret < 0) {
			pr_warn("ctrl %d failed to generate public key\n",
				ctrl->cntlid);
			kfree(ctrl->dh_key);
			ctrl->dh_key = NULL;
		}
	}

	return ret;
}

u8 nvmet_setup_auth(struct nvmet_ctrl *ctrl, struct nvmet_sq *sq, bool reset)
{
	int ret = 0;
	struct nvmet_host_link *p;
	struct nvmet_host *host = NULL;
	struct key *key;
	key_serial_t key_id;

	down_read(&nvmet_config_sem);
	if (nvmet_is_disc_subsys(ctrl->subsys))
		goto out_unlock;

	if (ctrl->subsys->allow_any_host)
		goto out_unlock;

	list_for_each_entry(p, &ctrl->subsys->hosts, entry) {
		pr_debug("check %s\n", nvmet_host_name(p->host));
		if (strcmp(nvmet_host_name(p->host), ctrl->hostnqn))
			continue;
		host = p->host;
		break;
	}
	if (!host) {
		pr_debug("host %s not found\n", ctrl->hostnqn);
		ret = NVME_AUTH_DHCHAP_FAILURE_FAILED;
		goto out_unlock;
	}

	if (!reset && nvmet_queue_tls_keyid(sq)) {
		pr_debug("host %s tls enabled\n", ctrl->hostnqn);
		goto out_unlock;
	}

	ret = nvmet_setup_dhgroup(ctrl, host->dhchap_dhgroup_id);
	if (ret < 0) {
		pr_warn("Failed to setup DH group");
		ret = NVME_AUTH_DHCHAP_FAILURE_DHGROUP_UNUSABLE;
		goto out_unlock;
	}

	if (!host->dhchap_key) {
		pr_debug("No authentication provided\n");
		goto out_unlock;
	}

	if (host->dhchap_hash_id == ctrl->shash_id) {
		pr_debug("Re-use existing hash ID %d\n",
			 ctrl->shash_id);
	} else {
		ctrl->shash_id = host->dhchap_hash_id;
	}

	key = key_get(host->dhchap_key);
	if (!key) {
		pr_warn("%s: host key %08x not found\n",
			 __func__, key_serial(host->dhchap_key));
		goto out_unlock;
	}
	down_read(&key->sem);
	ret = key_validate(key);
	if (!ret) {
		if (ctrl->host_key) {
			pr_debug("%s: drop host key %08x\n",
				 __func__, key_serial(ctrl->host_key));
			key_put(ctrl->host_key);
		}
		ctrl->host_key = key;
	}
	key_id = key_serial(key);
	up_read(&key->sem);
	if (ret) {
		pr_debug("key id %08x invalidated\n", key_id);
		key_put(key);
		key = ERR_PTR(-EKEYREVOKED);
	}
	pr_debug("%s: using dhchap hash %s key %08x\n", __func__,
		 nvme_auth_hmac_name(ctrl->shash_id), key_id);

	if (!host->dhchap_ctrl_key) {
		if (ctrl->ctrl_key) {
			pr_debug("%s: drop ctrl key %08x\n",
				 __func__, key_serial(ctrl->ctrl_key));
			key_put(ctrl->ctrl_key);
			ctrl->ctrl_key = NULL;
		}
		goto out_unlock;
	}

	key = key_get(host->dhchap_ctrl_key);
	if (!key) {
		pr_warn("%s: ctrl key %08x not found\n",
			__func__, key_serial(host->dhchap_ctrl_key));
		goto out_unlock;
	}
	down_read(&key->sem);
	ret = key_validate(key);
	if (!ret) {
		if (ctrl->ctrl_key) {
			pr_debug("%s: drop ctrl key %08x\n",
				 __func__, key_serial(ctrl->ctrl_key));
			key_put(ctrl->ctrl_key);
		}
		ctrl->ctrl_key = key;
	}
	key_id = key_serial(key);
	up_read(&key->sem);
	if (ret) {
		pr_debug("ctrl key id %08x invalidated\n", key_id);
		key_put(key);
		goto out_unlock;
	}
	pr_debug("%s: using dhchap ctrl hash %s key %08x\n", __func__,
		 nvme_auth_hmac_name(ctrl->shash_id), key_id);

out_unlock:
	up_read(&nvmet_config_sem);

	return ret;
}

void nvmet_auth_sq_free(struct nvmet_sq *sq)
{
	cancel_delayed_work(&sq->auth_expired_work);
#ifdef CONFIG_NVME_TARGET_TCP_TLS
	sq->tls_key = NULL;
#endif
	kfree(sq->dhchap_c1);
	sq->dhchap_c1 = NULL;
	kfree(sq->dhchap_c2);
	sq->dhchap_c2 = NULL;
	kfree(sq->dhchap_skey);
	sq->dhchap_skey = NULL;
}

void nvmet_destroy_auth(struct nvmet_ctrl *ctrl)
{
	ctrl->shash_id = 0;

	if (ctrl->dh_tfm) {
		crypto_free_kpp(ctrl->dh_tfm);
		ctrl->dh_tfm = NULL;
		ctrl->dh_gid = 0;
	}
	kfree_sensitive(ctrl->dh_key);
	ctrl->dh_key = NULL;

	if (ctrl->host_key) {
		pr_debug("%s: drop host key %08x\n",
			 __func__, key_serial(ctrl->host_key));
		key_put(ctrl->host_key);
		ctrl->host_key = NULL;
	}
	if (ctrl->ctrl_key) {
		pr_debug("%s: drop ctrl key %08x\n",
			 __func__, key_serial(ctrl->ctrl_key));
		key_put(ctrl->ctrl_key);
		ctrl->ctrl_key = NULL;
	}
#ifdef CONFIG_NVME_TARGET_TCP_TLS
	if (ctrl->tls_key) {
		key_put(ctrl->tls_key);
		ctrl->tls_key = NULL;
	}
#endif
}

bool nvmet_check_auth_status(struct nvmet_req *req)
{
	if (req->sq->ctrl->host_key) {
		if (req->sq->qid > 0)
			return true;
		if (!req->sq->authenticated)
			return false;
	}
	return true;
}

int nvmet_auth_host_hash(struct nvmet_req *req, u8 *response,
			 unsigned int shash_len)
{
	struct nvme_auth_hmac_ctx hmac;
	struct nvmet_ctrl *ctrl = req->sq->ctrl;
	u8 *challenge = req->sq->dhchap_c1;
	u8 *transformed_secret;
	size_t transformed_len;
	u8 buf[4];
	int ret;

	ret = nvme_auth_transform_key(ctrl->host_key, ctrl->hostnqn,
				      &transformed_secret);
	if (ret < 0)
		return ret;
	transformed_len = ret;

	ret = nvme_auth_hmac_init(&hmac, ctrl->shash_id, transformed_secret,
				  transformed_len);
	if (ret)
		goto out_free_response;

	if (shash_len != nvme_auth_hmac_hash_len(ctrl->shash_id)) {
		pr_err("%s: hash len mismatch (len %u digest %zu)\n", __func__,
		       shash_len, nvme_auth_hmac_hash_len(ctrl->shash_id));
		ret = -EINVAL;
		goto out_free_response;
	}

	if (ctrl->dh_gid != NVME_AUTH_DHGROUP_NULL) {
		challenge = kmalloc(shash_len, GFP_KERNEL);
		if (!challenge) {
			ret = -ENOMEM;
			goto out_free_response;
		}
		ret = nvme_auth_augmented_challenge(ctrl->shash_id,
						    req->sq->dhchap_skey,
						    req->sq->dhchap_skey_len,
						    req->sq->dhchap_c1,
						    challenge, shash_len);
		if (ret)
			goto out_free_challenge;
	}

	pr_debug("ctrl %d qid %d host response seq %u transaction %d\n",
		 ctrl->cntlid, req->sq->qid, req->sq->dhchap_s1,
		 req->sq->dhchap_tid);

	nvme_auth_hmac_update(&hmac, challenge, shash_len);

	put_unaligned_le32(req->sq->dhchap_s1, buf);
	nvme_auth_hmac_update(&hmac, buf, 4);

	put_unaligned_le16(req->sq->dhchap_tid, buf);
	nvme_auth_hmac_update(&hmac, buf, 2);

	*buf = req->sq->sc_c;
	nvme_auth_hmac_update(&hmac, buf, 1);
	nvme_auth_hmac_update(&hmac, "HostHost", 8);
	memset(buf, 0, 4);
	nvme_auth_hmac_update(&hmac, ctrl->hostnqn, strlen(ctrl->hostnqn));
	nvme_auth_hmac_update(&hmac, buf, 1);
	nvme_auth_hmac_update(&hmac, ctrl->subsys->subsysnqn,
			      strlen(ctrl->subsys->subsysnqn));
	nvme_auth_hmac_final(&hmac, response);
	ret = 0;
out_free_challenge:
	if (challenge != req->sq->dhchap_c1)
		kfree(challenge);
out_free_response:
	memzero_explicit(&hmac, sizeof(hmac));
	kfree_sensitive(transformed_secret);
	return ret;
}

int nvmet_auth_ctrl_hash(struct nvmet_req *req, u8 *response,
			 unsigned int shash_len)
{
	struct nvme_auth_hmac_ctx hmac;
	struct nvmet_ctrl *ctrl = req->sq->ctrl;
	u8 *challenge = req->sq->dhchap_c2;
	u8 *transformed_secret;
	size_t transformed_len;
	u8 buf[4];
	int ret;

	ret = nvme_auth_transform_key(ctrl->ctrl_key,
				      ctrl->subsys->subsysnqn,
				      &transformed_secret);
	if (ret < 0)
		return ret;
	transformed_len = ret;

	ret = nvme_auth_hmac_init(&hmac, ctrl->shash_id, transformed_secret,
				  transformed_len);
	if (ret)
		goto out_free_response;

	if (shash_len != nvme_auth_hmac_hash_len(ctrl->shash_id)) {
		pr_err("%s: hash len mismatch (len %u digest %zu)\n", __func__,
		       shash_len, nvme_auth_hmac_hash_len(ctrl->shash_id));
		ret = -EINVAL;
		goto out_free_response;
	}

	if (ctrl->dh_gid != NVME_AUTH_DHGROUP_NULL) {
		challenge = kmalloc(shash_len, GFP_KERNEL);
		if (!challenge) {
			ret = -ENOMEM;
			goto out_free_response;
		}
		ret = nvme_auth_augmented_challenge(ctrl->shash_id,
						    req->sq->dhchap_skey,
						    req->sq->dhchap_skey_len,
						    req->sq->dhchap_c2,
						    challenge, shash_len);
		if (ret)
			goto out_free_challenge;
	}

	nvme_auth_hmac_update(&hmac, challenge, shash_len);

	put_unaligned_le32(req->sq->dhchap_s2, buf);
	nvme_auth_hmac_update(&hmac, buf, 4);

	put_unaligned_le16(req->sq->dhchap_tid, buf);
	nvme_auth_hmac_update(&hmac, buf, 2);

	memset(buf, 0, 4);
	nvme_auth_hmac_update(&hmac, buf, 1);
	nvme_auth_hmac_update(&hmac, "Controller", 10);
	nvme_auth_hmac_update(&hmac, ctrl->subsys->subsysnqn,
			      strlen(ctrl->subsys->subsysnqn));
	nvme_auth_hmac_update(&hmac, buf, 1);
	nvme_auth_hmac_update(&hmac, ctrl->hostnqn, strlen(ctrl->hostnqn));
	nvme_auth_hmac_final(&hmac, response);
	ret = 0;
out_free_challenge:
	if (challenge != req->sq->dhchap_c2)
		kfree(challenge);
out_free_response:
	memzero_explicit(&hmac, sizeof(hmac));
	kfree_sensitive(transformed_secret);
	return ret;
}

int nvmet_auth_ctrl_exponential(struct nvmet_req *req,
				u8 *buf, int buf_size)
{
	struct nvmet_ctrl *ctrl = req->sq->ctrl;
	int ret = 0;

	if (!ctrl->dh_key) {
		pr_warn("ctrl %d no DH public key!\n", ctrl->cntlid);
		return -ENOKEY;
	}
	if (buf_size != ctrl->dh_keysize) {
		pr_warn("ctrl %d DH public key size mismatch, need %zu is %d\n",
			ctrl->cntlid, ctrl->dh_keysize, buf_size);
		ret = -EINVAL;
	} else {
		memcpy(buf, ctrl->dh_key, buf_size);
		pr_debug("%s: ctrl %d public key %*ph\n", __func__,
			 ctrl->cntlid, (int)buf_size, buf);
	}

	return ret;
}

int nvmet_auth_ctrl_sesskey(struct nvmet_req *req,
			    const u8 *pkey, int pkey_size)
{
	struct nvmet_ctrl *ctrl = req->sq->ctrl;
	int ret;

	req->sq->dhchap_skey_len = ctrl->dh_keysize;
	req->sq->dhchap_skey = kzalloc(req->sq->dhchap_skey_len, GFP_KERNEL);
	if (!req->sq->dhchap_skey)
		return -ENOMEM;
	ret = nvme_auth_gen_shared_secret(ctrl->dh_tfm,
					  pkey, pkey_size,
					  req->sq->dhchap_skey,
					  req->sq->dhchap_skey_len);
	if (ret)
		pr_debug("failed to compute shared secret, err %d\n", ret);
	else
		pr_debug("%s: shared secret %*ph\n", __func__,
			 (int)req->sq->dhchap_skey_len,
			 req->sq->dhchap_skey);

	return ret;
}

void nvmet_auth_insert_psk(struct nvmet_sq *sq)
{
	int hash_len = nvme_auth_hmac_hash_len(sq->ctrl->shash_id);
	u8 *psk, *tls_psk;
	char *digest;
	size_t psk_len;
	int ret;
#ifdef CONFIG_NVME_TARGET_TCP_TLS
	struct key *tls_key = NULL;
#endif

	ret = nvme_auth_generate_psk(sq->ctrl->shash_id,
				     sq->dhchap_skey,
				     sq->dhchap_skey_len,
				     sq->dhchap_c1, sq->dhchap_c2,
				     hash_len, &psk, &psk_len);
	if (ret) {
		pr_warn("%s: ctrl %d qid %d failed to generate PSK, error %d\n",
			__func__, sq->ctrl->cntlid, sq->qid, ret);
		return;
	}
	ret = nvme_auth_generate_digest(sq->ctrl->shash_id, psk, psk_len,
					sq->ctrl->subsys->subsysnqn,
					sq->ctrl->hostnqn, &digest);
	if (ret) {
		pr_warn("%s: ctrl %d qid %d failed to generate digest, error %d\n",
			__func__, sq->ctrl->cntlid, sq->qid, ret);
		goto out_free_psk;
	}
	ret = nvme_auth_derive_tls_psk(sq->ctrl->shash_id, psk, psk_len,
				       digest, &tls_psk);
	if (ret) {
		pr_warn("%s: ctrl %d qid %d failed to derive TLS PSK, error %d\n",
			__func__, sq->ctrl->cntlid, sq->qid, ret);
		goto out_free_digest;
	}
#ifdef CONFIG_NVME_TARGET_TCP_TLS
	tls_key = nvme_tls_psk_refresh(NULL, sq->ctrl->hostnqn,
				       sq->ctrl->subsys->subsysnqn,
				       sq->ctrl->shash_id, tls_psk, psk_len,
				       digest);
	if (IS_ERR(tls_key)) {
		pr_warn("%s: ctrl %d qid %d failed to refresh key, error %ld\n",
			__func__, sq->ctrl->cntlid, sq->qid, PTR_ERR(tls_key));
		tls_key = NULL;
	}
	if (sq->ctrl->tls_key)
		key_put(sq->ctrl->tls_key);
	sq->ctrl->tls_key = tls_key;
#endif
	kfree_sensitive(tls_psk);
out_free_digest:
	kfree_sensitive(digest);
out_free_psk:
	kfree_sensitive(psk);
}
