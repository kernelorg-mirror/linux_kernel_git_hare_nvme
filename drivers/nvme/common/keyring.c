// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2023 Hannes Reinecke, SUSE Labs
 */

#include <linux/module.h>
#include <linux/crc32.h>
#include <linux/base64.h>
#include <linux/unaligned.h>
#include <linux/seq_file.h>
#include <linux/key-type.h>
#include <keys/user-type.h>
#include <linux/nvme.h>
#include <linux/nvme-tcp.h>
#include <linux/nvme-keyring.h>

static struct key *nvme_keyring;

key_serial_t nvme_keyring_id(void)
{
	return nvme_keyring->serial;
}
EXPORT_SYMBOL_GPL(nvme_keyring_id);

static bool nvme_tls_psk_revoked(struct key *psk)
{
	return test_bit(KEY_FLAG_REVOKED, &psk->flags) ||
		test_bit(KEY_FLAG_INVALIDATED, &psk->flags);
}

struct key *nvme_tls_key_lookup(key_serial_t key_id)
{
	struct key *key = key_lookup(key_id);

	if (IS_ERR(key)) {
		pr_err("key id %08x not found\n", key_id);
		return key;
	}
	if (nvme_tls_psk_revoked(key)) {
		pr_err("key id %08x revoked\n", key_id);
		return ERR_PTR(-EKEYREVOKED);
	}
	return key;
}
EXPORT_SYMBOL_GPL(nvme_tls_key_lookup);

static void nvme_tls_psk_describe(const struct key *key, struct seq_file *m)
{
	seq_puts(m, key->description);
	seq_printf(m, ": %u", key->datalen);
}

static bool nvme_tls_psk_match(const struct key *key,
			       const struct key_match_data *match_data)
{
	const char *match_id;
	size_t match_len;

	if (!key->description) {
		pr_debug("%s: no key description\n", __func__);
		return false;
	}
	if (!match_data->raw_data) {
		pr_debug("%s: no match data\n", __func__);
		return false;
	}
	match_id = match_data->raw_data;
	match_len = strlen(match_id);
	pr_debug("%s: match '%s' '%s' len %zd\n",
		 __func__, match_id, key->description, match_len);
	return !memcmp(key->description, match_id, match_len);
}

static int nvme_tls_psk_match_preparse(struct key_match_data *match_data)
{
	match_data->lookup_type = KEYRING_SEARCH_LOOKUP_ITERATE;
	match_data->cmp = nvme_tls_psk_match;
	return 0;
}

static struct key_type nvme_tls_psk_key_type = {
	.name           = "psk",
	.flags          = KEY_TYPE_NET_DOMAIN,
	.preparse       = user_preparse,
	.free_preparse  = user_free_preparse,
	.match_preparse = nvme_tls_psk_match_preparse,
	.instantiate    = generic_key_instantiate,
	.revoke         = user_revoke,
	.destroy        = user_destroy,
	.describe       = nvme_tls_psk_describe,
	.read           = user_read,
};

static struct key *nvme_tls_psk_lookup(struct key *keyring,
		const char *hostnqn, const char *subnqn,
		u8 hmac, u8 psk_ver, bool generated)
{
	char *identity;
	size_t identity_len = (NVMF_NQN_SIZE) * 2 + 11;
	key_ref_t keyref;
	key_serial_t keyring_id;

	identity = kzalloc(identity_len, GFP_KERNEL);
	if (!identity)
		return ERR_PTR(-ENOMEM);

	snprintf(identity, identity_len, "NVMe%u%c%02u %s %s",
		 psk_ver, generated ? 'G' : 'R', hmac, hostnqn, subnqn);

	if (!keyring)
		keyring = nvme_keyring;
	keyring_id = key_serial(keyring);
	pr_debug("keyring %x lookup tls psk '%s'\n",
		 keyring_id, identity);
	keyref = keyring_search(make_key_ref(keyring, true),
				&nvme_tls_psk_key_type,
				identity, false);
	if (IS_ERR(keyref)) {
		pr_debug("lookup tls psk '%s' failed, error %ld\n",
			 identity, PTR_ERR(keyref));
		kfree(identity);
		return ERR_PTR(-ENOKEY);
	}
	kfree(identity);

	return key_ref_to_ptr(keyref);
}

/**
 * nvme_tls_psk_refresh - Refresh TLS PSK
 * @keyring: Keyring holding the TLS PSK
 * @hostnqn: Host NQN to use
 * @subnqn: Subsystem NQN to use
 * @hmac_id: Hash function identifier
 * @data: TLS PSK key material
 * @data_len: Length of @data
 * @digest: TLS PSK digest
 *
 * Refresh a generated version 1 TLS PSK with the identity generated
 * from @hmac_id, @hostnqn, @subnqn, and @digest in the keyring given
 * by @keyring.
 *
 * Returns the updated key success or an error pointer otherwise.
 */
struct key *nvme_tls_psk_refresh(struct key *keyring,
		const char *hostnqn, const char *subnqn, u8 hmac_id,
		u8 *data, size_t data_len, const char *digest)
{
	key_perm_t keyperm =
		KEY_POS_SEARCH | KEY_POS_VIEW | KEY_POS_READ |
		KEY_POS_WRITE | KEY_POS_LINK | KEY_POS_SETATTR |
		KEY_USR_SEARCH | KEY_USR_VIEW | KEY_USR_READ;
	char *identity;
	key_ref_t keyref;
	key_serial_t keyring_id;
	struct key *key;

	if (!hostnqn || !subnqn || !data || !data_len)
		return ERR_PTR(-EINVAL);

	identity = kasprintf(GFP_KERNEL, "NVMe1G%02d %s %s %s",
		 hmac_id, hostnqn, subnqn, digest);
	if (!identity)
		return ERR_PTR(-ENOMEM);

	if (!keyring)
		keyring = nvme_keyring;
	keyring_id = key_serial(keyring);
	pr_debug("keyring %x refresh tls psk '%s'\n",
		 keyring_id, identity);
	keyref = key_create_or_update(make_key_ref(keyring, true),
				"psk", identity, data, data_len,
				keyperm, KEY_ALLOC_NOT_IN_QUOTA |
				      KEY_ALLOC_BUILT_IN |
				      KEY_ALLOC_BYPASS_RESTRICTION);
	if (IS_ERR(keyref)) {
		pr_debug("refresh tls psk '%s' failed, error %ld\n",
			 identity, PTR_ERR(keyref));
		kfree(identity);
		return ERR_PTR(-ENOKEY);
	}
	kfree(identity);
	/*
	 * Set the default timeout to 1 hour
	 * as suggested in TP8018.
	 */
	key = key_ref_to_ptr(keyref);
	key_set_timeout(key, 3600);
	return key;
}
EXPORT_SYMBOL_GPL(nvme_tls_psk_refresh);

/*
 * NVMe PSK priority list
 *
 * 'Retained' PSKs (ie 'generated == false') should be preferred to 'generated'
 * PSKs, PSKs with hash (psk_ver 1) should be preferred to PSKs without hash
 * (psk_ver 0), and SHA-384 should be preferred to SHA-256.
 */
static struct nvme_tls_psk_priority_list {
	bool generated;
	u8 psk_ver;
	enum nvme_tcp_tls_cipher cipher;
} nvme_tls_psk_prio[] = {
	{ .generated = false,
	  .psk_ver = 1,
	  .cipher = NVME_TCP_TLS_CIPHER_SHA384, },
	{ .generated = false,
	  .psk_ver = 1,
	  .cipher = NVME_TCP_TLS_CIPHER_SHA256, },
	{ .generated = false,
	  .psk_ver = 0,
	  .cipher = NVME_TCP_TLS_CIPHER_SHA384, },
	{ .generated = false,
	  .psk_ver = 0,
	  .cipher = NVME_TCP_TLS_CIPHER_SHA256, },
	{ .generated = true,
	  .psk_ver = 1,
	  .cipher = NVME_TCP_TLS_CIPHER_SHA384, },
	{ .generated = true,
	  .psk_ver = 1,
	  .cipher = NVME_TCP_TLS_CIPHER_SHA256, },
	{ .generated = true,
	  .psk_ver = 0,
	  .cipher = NVME_TCP_TLS_CIPHER_SHA384, },
	{ .generated = true,
	  .psk_ver = 0,
	  .cipher = NVME_TCP_TLS_CIPHER_SHA256, },
};

/*
 * nvme_tls_psk_default - Return the preferred PSK to use for TLS ClientHello
 */
key_serial_t nvme_tls_psk_default(struct key *keyring,
		      const char *hostnqn, const char *subnqn)
{
	struct key *tls_key;
	key_serial_t tls_key_id;
	int prio;

	for (prio = 0; prio < ARRAY_SIZE(nvme_tls_psk_prio); prio++) {
		bool generated = nvme_tls_psk_prio[prio].generated;
		u8 ver = nvme_tls_psk_prio[prio].psk_ver;
		enum nvme_tcp_tls_cipher cipher = nvme_tls_psk_prio[prio].cipher;

		tls_key = nvme_tls_psk_lookup(keyring, hostnqn, subnqn,
					      cipher, ver, generated);
		if (!IS_ERR(tls_key)) {
			tls_key_id = tls_key->serial;
			key_put(tls_key);
			return tls_key_id;
		}
	}
	return 0;
}
EXPORT_SYMBOL_GPL(nvme_tls_psk_default);

static void nvme_dhchap_psk_describe(const struct key *key, struct seq_file *m)
{
	seq_puts(m, key->description);
	seq_printf(m, ": %u", key->datalen);
}

static bool nvme_dhchap_psk_match(const struct key *key,
				  const struct key_match_data *match_data)
{
	const char *match_id;
	size_t match_len;

	if (!key->description) {
		pr_debug("%s: no key description\n", __func__);
		return false;
	}
	if (!match_data->raw_data) {
		pr_debug("%s: no match data\n", __func__);
		return false;
	}
	match_id = match_data->raw_data;
	match_len = strlen(match_id);
	pr_debug("%s: match '%s' '%s' len %zd\n",
		 __func__, match_id, key->description, match_len);

	return !memcmp(key->description, match_id, match_len);
}

static int nvme_dhchap_psk_match_preparse(struct key_match_data *match_data)
{
	match_data->lookup_type = KEYRING_SEARCH_LOOKUP_ITERATE;
	match_data->cmp = nvme_dhchap_psk_match;
	return 0;
}

/**
 * nvme_dhchap_psk_preparse - prepare DH-HMAC-CHAP key data
 * @prep: preparsed payload of the key data
 *
 * Decode the DH-HMAC-CHAP key data passed in in @prep and
 * store the resulting binary data. The binary data includes
 * space for the CRC, the version, and the hmac identifier,
 * but the data length is just the key data without the CRC.
 * This allows the user to read the key data via the
 * 'user_read()' function, but also to export the full
 * key data including CRC via the 'read' callback from the key type.
 */
static int nvme_dhchap_psk_preparse(struct key_preparsed_payload *prep)
{
	struct user_key_payload *upayload;
	size_t datalen = prep->datalen, keylen;
	int ret;
	u32 crc;
	u8 version, hmac;

	if (!prep->data) {
		pr_debug("%s: Empty data", __func__);
		prep->payload.data[0] = NULL;
		prep->quotalen = 0;
		return -EINVAL;
	}

	if (sscanf(prep->data, "DHHC-%01hhu:%02hhu:%*s", &version, &hmac) != 2) {
		pr_debug("%s: invalid key data '%s'\n", __func__,
			 (char *)prep->data);
		prep->payload.data[0] = NULL;
		prep->quotalen = 0;
		return -EINVAL;
	}

	/* skip header and final ':' character */
	datalen -= 11;

	/* keylen is the key length, 4 bytes CRC, 1 byte version, and 1 byte HMAC identifier */
	switch (datalen) {
	case 48:
		keylen = 38;
		break;
	case 72:
		keylen = 54;
		break;
	case 92:
		keylen = 70;
		break;
	default:
		pr_debug("%s: Invalid data length %lu\n", __func__, datalen);
		prep->payload.data[0] = NULL;
		prep->quotalen = 0;
		return -EINVAL;
	}

	upayload = kzalloc(sizeof(*upayload) + keylen, GFP_KERNEL);
	if (!upayload) {
		prep->payload.data[0] = NULL;
		prep->quotalen = 0;
		return -ENOMEM;
	}

	/* decode the data */
	prep->quotalen = keylen;
	prep->payload.data[0] = upayload;
	ret = base64_decode(prep->data + 10, datalen, upayload->data);
	if (ret < 0) {
		pr_debug("%s: Failed to decode key %s\n",
			 __func__, (char *)prep->data + 10);
		return ret;
	}
	ret -= 4;
	crc = ~crc32(~0, upayload->data, ret);
	if (get_unaligned_le32(upayload->data + ret) != crc) {
		pr_debug("%s: CRC mismatch for key\n", __func__);
		/* CRC mismatch */
		return -EKEYREJECTED;
	}
	upayload->data[ret + 4] = version;
	upayload->data[ret + 5] = hmac;
	upayload->datalen = ret;
	return 0;
}

static long nvme_dhchap_psk_read(const struct key *key, char *buffer, size_t buflen)
{
	const struct user_key_payload *upayload;
	size_t datalen, keylen;
	u8 version, hmac;
	long ret;

	upayload = user_key_payload_locked(key);
	switch (upayload->datalen) {
	    case 32:
		keylen = 59;
		break;
	    case 48:
		keylen = 83;
		break;
	    case 64:
		keylen = 103;
		break;
	    default:
		return -EINVAL;
	}

	if (!buffer || buflen == 0)
		return keylen;

	if (buflen < keylen)
		return -EINVAL;

	memset(buffer, 0, buflen);
	version = upayload->data[upayload->datalen + 4];
	hmac = upayload->data[upayload->datalen + 5];
	ret = sprintf(buffer, "DHHC-%01hhu:%02hhu:", version, hmac);
	if (ret < 0)
		return -ENOKEY;
	/* Include the trailing CRC */
	datalen = upayload->datalen + 4;
	ret += base64_encode(upayload->data, datalen, buffer + ret);
	buffer[ret] = ':';
	ret++;
	return ret;
}

static struct key_type nvme_dhchap_psk_key_type = {
	.name           = "dhchap",
	.flags          = KEY_TYPE_NET_DOMAIN,
	.preparse       = nvme_dhchap_psk_preparse,
	.free_preparse  = user_free_preparse,
	.match_preparse = nvme_dhchap_psk_match_preparse,
	.instantiate    = generic_key_instantiate,
	.revoke         = user_revoke,
	.destroy        = user_destroy,
	.describe       = nvme_dhchap_psk_describe,
	.read           = nvme_dhchap_psk_read,
};

struct key *nvme_dhchap_psk_refresh(struct key *keyring,
		const u8 *data, size_t data_len)
{
	key_perm_t keyperm =
		KEY_POS_SEARCH | KEY_POS_VIEW | KEY_POS_READ |
		KEY_POS_WRITE | KEY_POS_LINK | KEY_POS_SETATTR |
		KEY_USR_SEARCH | KEY_USR_VIEW | KEY_USR_READ;
	char *identity;
	key_ref_t keyref;
	key_serial_t keyring_id;
	struct key *key;
	uuid_t key_uuid;

	if (data == NULL || !data_len)
		return ERR_PTR(-EINVAL);

	generate_random_uuid(key_uuid.b);
	identity = kasprintf(GFP_KERNEL, "%pU", &key_uuid);
	if (!identity)
		return ERR_PTR(-ENOMEM);
	if (!keyring)
		keyring = nvme_keyring;
	keyring_id = key_serial(keyring);

	pr_debug("keyring %x generate dhchap psk '%s'\n",
		 keyring_id, identity);
	keyref = key_create(make_key_ref(keyring, true),
			    "dhchap", identity, data, data_len,
			    keyperm, KEY_ALLOC_NOT_IN_QUOTA |
			    KEY_ALLOC_BUILT_IN |
			    KEY_ALLOC_BYPASS_RESTRICTION);
	if (IS_ERR(keyref)) {
		pr_warn("refresh dhchap psk '%s' failed, error %ld\n",
			identity, PTR_ERR(keyref));
		kfree(identity);
		return ERR_PTR(-ENOKEY);
	}
	key = key_ref_to_ptr(keyref);
	pr_debug("generated dhchap psk %08x\n", key_serial(key));
	kfree(identity);
	return key;
}
EXPORT_SYMBOL_GPL(nvme_dhchap_psk_refresh);

struct key *nvme_dhchap_psk_lookup(struct key *keyring, const char *identity)
{
	key_ref_t keyref;
	key_serial_t keyring_id;

	if (!keyring)
		keyring = nvme_keyring;
	keyring_id = key_serial(keyring);
	pr_debug("keyring %x lookup dhchap psk '%s'\n",
		 keyring_id, identity);

	keyref = keyring_search(make_key_ref(keyring, true),
				&nvme_dhchap_psk_key_type,
				identity, false);
	if (IS_ERR(keyref)) {
		pr_debug("lookup dhchap psk '%s' failed, error %ld\n",
			 identity, PTR_ERR(keyref));
		return ERR_PTR(-ENOKEY);
	}

	return key_ref_to_ptr(keyref);
}
EXPORT_SYMBOL_GPL(nvme_dhchap_psk_lookup);

u8 nvme_dhchap_psk_hash(struct key *key)
{
	const struct user_key_payload *upayload;
	u8 hmac;

	if (!key)
		return 0;
	upayload = user_key_payload_locked(key);
	hmac = upayload->data[upayload->datalen + 5];
	return hmac;
}
EXPORT_SYMBOL_GPL(nvme_dhchap_psk_hash);

size_t nvme_dhchap_psk_len(struct key *key)
{
	const struct user_key_payload *upayload;

	if (!key)
		return 0;
	upayload = user_key_payload_locked(key);
	return upayload->datalen;
}
EXPORT_SYMBOL_GPL(nvme_dhchap_psk_len);

static int __init nvme_keyring_init(void)
{
	int err;

	nvme_keyring = keyring_alloc(".nvme",
				     GLOBAL_ROOT_UID, GLOBAL_ROOT_GID,
				     current_cred(),
				     (KEY_POS_ALL & ~KEY_POS_SETATTR) |
				     (KEY_USR_ALL & ~KEY_USR_SETATTR),
				     KEY_ALLOC_NOT_IN_QUOTA, NULL, NULL);
	if (IS_ERR(nvme_keyring))
		return PTR_ERR(nvme_keyring);

	err = register_key_type(&nvme_tls_psk_key_type);
	if (err) {
		key_put(nvme_keyring);
		return err;
	}
	err = register_key_type(&nvme_dhchap_psk_key_type);
	if (err) {
		unregister_key_type(&nvme_tls_psk_key_type);
		key_put(nvme_keyring);
		return err;
	}
	return 0;
}

static void __exit nvme_keyring_exit(void)
{
	unregister_key_type(&nvme_dhchap_psk_key_type);
	unregister_key_type(&nvme_tls_psk_key_type);
	key_revoke(nvme_keyring);
	key_put(nvme_keyring);
}

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Hannes Reinecke <hare@suse.de>");
MODULE_DESCRIPTION("NVMe Keyring implementation");
module_init(nvme_keyring_init);
module_exit(nvme_keyring_exit);
