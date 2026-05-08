// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * mount.c - operations for initializing and mounting configfs.
 *
 * Based on sysfs:
 * 	sysfs is Copyright (C) 2001, 2002, 2003 Patrick Mochel
 *
 * configfs Copyright (C) 2005 Oracle.  All rights reserved.
 */

#include <linux/fs.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/fs_context.h>
#include <linux/pagemap.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/mnt_namespace.h>
#include <net/net_namespace.h>

#include <linux/configfs.h>
#include "configfs_internal.h"

/* Random magic number */
#define CONFIGFS_MAGIC 0x62656570

static struct vfsmount *configfs_mount = NULL;
struct kmem_cache *configfs_dir_cachep;
static int configfs_mnt_count = 0;


static const char root_name[] = "root";

struct configfs_fs_context {
	void *ns_tag;
};

struct configfs_super_info {
	struct configfs_dirent root;
	struct config_group group;
	struct super_block *sb;
	void *ns;
};

static void configfs_free_inode(struct inode *inode)
{
	if (S_ISLNK(inode->i_mode))
		kfree(inode->i_link);
	free_inode_nonrcu(inode);
}

static const struct super_operations configfs_ops = {
	.statfs		= simple_statfs,
	.drop_inode	= inode_just_drop,
	.free_inode	= configfs_free_inode,
};

int configfs_is_root(struct config_item *item)
{
	struct configfs_dirent *sd =
		item->ci_dentry->d_fsdata;
	return sd->s_type == CONFIGFS_ROOT;
}

static int configfs_fill_super(struct super_block *sb, struct fs_context *fc)
{
	struct configfs_fs_context *cfc = fc->fs_private;
	struct configfs_super_info *info;
	struct inode *inode;
	struct dentry *root;

	info = kzalloc_obj(*info);
	if (!info)
		return -ENOMEM;

	INIT_LIST_HEAD(&info->root.s_sibling);
	INIT_LIST_HEAD(&info->root.s_children);
	info->ns = cfc->ns_tag;
	info->root.s_type = CONFIGFS_ROOT;
	info->root.s_element = &info->group.cg_item;
	info->group.cg_item.ci_name = (char *)root_name;
	sb->s_blocksize = PAGE_SIZE;
	sb->s_blocksize_bits = PAGE_SHIFT;
	sb->s_magic = CONFIGFS_MAGIC;
	sb->s_op = &configfs_ops;
	sb->s_time_gran = 1;

	inode = configfs_new_inode(S_IFDIR | S_IRWXU | S_IRUGO | S_IXUGO,
				   &info->root, sb);
	if (inode) {
		inode->i_op = &configfs_root_inode_operations;
		inode->i_fop = &configfs_dir_operations;
		/* directory inodes start off with i_nlink == 2 (for "." entry) */
		inc_nlink(inode);
	} else {
		pr_debug("could not get root inode\n");
		return -ENOMEM;
	}

	root = d_make_root(inode);
	if (!root) {
		pr_debug("%s: could not get root dentry!\n",__func__);
		return -ENOMEM;
	}
	config_group_init(&info->group);
	info->group.cg_item.ci_dentry = root;
	root->d_fsdata = &info->root;
	sb->s_root = root;
	info->sb = sb;
	sb->s_fs_info = info;
	set_default_d_op(sb, &configfs_dentry_ops); /* the rest get that */
	sb->s_d_flags |= DCACHE_DONTCACHE;
	return 0;
}

static int configfs_test_super(struct super_block *s, struct fs_context *fc)
{
	struct configfs_super_info *info =
		(struct configfs_super_info *)s->s_fs_info;
	struct configfs_fs_context *cfc = fc->fs_private;

	return (info->ns == cfc->ns_tag);
}

static int configfs_set_super(struct super_block *sb, struct fs_context *fc)
{
	struct configfs_fs_context *cfc = fc->fs_private;

	cfc->ns_tag = NULL;
	return set_anon_super_fc(sb, fc);
}

static int configfs_get_tree(struct fs_context *fc)
{
	struct super_block *sb;
	int err;

	sb = sget_fc(fc, configfs_test_super, configfs_set_super);
	if (IS_ERR(sb))
		return PTR_ERR(sb);
	if (!sb->s_root) {
		err = configfs_fill_super(sb, fc);
		if (err) {
			deactivate_locked_super(sb);
			return err;
		}
		sb->s_flags |= SB_ACTIVE;
	}
	fc->root = dget(sb->s_root);
	return 0;
}

static void configfs_fs_context_free(struct fs_context *fc)
{
	struct configfs_fs_context *cfc = fc->fs_private;

	if (cfc->ns_tag)
		kobj_ns_drop(KOBJ_NS_TYPE_NET, cfc->ns_tag);
	kfree(cfc);

	kfree(fc->s_fs_info);
	fc->s_fs_info = NULL;
}

static const struct fs_context_operations configfs_context_ops = {
	.get_tree	= configfs_get_tree,
	.free		= configfs_fs_context_free,
};

static int configfs_init_fs_context(struct fs_context *fc)
{
	struct configfs_fs_context *cfc;
	struct net *netns;

	cfc = kzalloc_obj(*cfc);
	if (!cfc)
		return -ENOMEM;
	cfc->ns_tag = netns = kobj_ns_grab_current(KOBJ_NS_TYPE_NET);
	fc->fs_private = cfc;
	fc->ops = &configfs_context_ops;
	if (netns) {
		put_user_ns(fc->user_ns);
		fc->user_ns = get_user_ns(netns->user_ns);
	}
	fc->global = true;
	return 0;
}

static void configfs_kill_sb(struct super_block *sb)
{
	struct configfs_super_info *info =
		(struct configfs_super_info *)(sb->s_fs_info);
	void *ns = info->ns;

	kill_anon_super(sb);
	kfree(info);
	kobj_ns_drop(KOBJ_NS_TYPE_NET, ns);
}

static struct file_system_type configfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "configfs",
	.init_fs_context = configfs_init_fs_context,
	.kill_sb	= configfs_kill_sb,
	.fs_flags	= FS_USERNS_MOUNT,
};
MODULE_ALIAS_FS("configfs");

struct dentry *configfs_pin_fs(void)
{
	int err = simple_pin_fs(&configfs_fs_type, &configfs_mount,
			     &configfs_mnt_count);
	return err ? ERR_PTR(err) : configfs_mount->mnt_root;
}

void configfs_release_fs(void)
{
	simple_release_fs(&configfs_mount, &configfs_mnt_count);
}


static int __init configfs_init(void)
{
	int err = -ENOMEM;

	configfs_dir_cachep = kmem_cache_create("configfs_dir_cache",
						sizeof(struct configfs_dirent),
						0, 0, NULL);
	if (!configfs_dir_cachep)
		goto out;

	err = sysfs_create_mount_point(kernel_kobj, "config");
	if (err)
		goto out2;

	err = register_filesystem(&configfs_fs_type);
	if (err)
		goto out3;

	return 0;
out3:
	pr_err("Unable to register filesystem!\n");
	sysfs_remove_mount_point(kernel_kobj, "config");
out2:
	kmem_cache_destroy(configfs_dir_cachep);
	configfs_dir_cachep = NULL;
out:
	return err;
}

static void __exit configfs_exit(void)
{
	unregister_filesystem(&configfs_fs_type);
	sysfs_remove_mount_point(kernel_kobj, "config");
	kmem_cache_destroy(configfs_dir_cachep);
	configfs_dir_cachep = NULL;
}

MODULE_AUTHOR("Oracle");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.0.2");
MODULE_DESCRIPTION("Simple RAM filesystem for user driven kernel subsystem configuration.");

core_initcall(configfs_init);
module_exit(configfs_exit);
