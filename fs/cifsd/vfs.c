// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@gmail.com>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/backing-dev.h>
#include <linux/writeback.h>
#include <linux/version.h>
#include <linux/xattr.h>
#include <linux/falloc.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/fsnotify.h>
#include <linux/dcache.h>
#include <linux/fiemap.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/xacct.h>
#else
#include <linux/sched.h>
#endif

#include "glob.h"
#include "oplock.h"
#include "connection.h"
#include "buffer_pool.h"
#include "vfs.h"
#include "vfs_cache.h"

#include "time_wrappers.h"
#include "smb_common.h"
#include "mgmt/share_config.h"
#include "mgmt/tree_connect.h"
#include "mgmt/user_session.h"
#include "mgmt/user_config.h"

static char *extract_last_component(char *path)
{
	char *p = strrchr(path, '/');

	if (p && p[1] != '\0') {
		*p = '\0';
		p++;
	} else {
		cifsd_err("Invalid path %s\n", path);
	}
	return p;
}

static void roolback_path_modification(char *filename)
{
	if (filename) {
		filename--;
		*filename = '/';
	}
}

static void cifsd_vfs_inode_uid_gid(struct cifsd_work *work,
				    struct inode *inode)
{
	struct cifsd_share_config *share = work->tcon->share_conf;
	unsigned int uid = user_uid(work->sess->user);
	unsigned int gid = user_gid(work->sess->user);

	if (share->force_uid != 0)
		uid = share->force_uid;
	if (share->force_gid != 0)
		gid = share->force_gid;

	i_uid_write(inode, uid);
	i_gid_write(inode, gid);
}

static void cifsd_vfs_inherit_owner(struct cifsd_work *work,
				    struct inode *parent_inode,
				    struct inode *inode)
{
	if (!test_share_config_flag(work->tcon->share_conf,
				   CIFSD_SHARE_FLAG_INHERIT_OWNER))
		return;

	i_uid_write(inode, i_uid_read(parent_inode));
}

static void cifsd_vfs_inherit_smack(struct cifsd_work *work,
				    struct dentry *dir_dentry,
				    struct dentry *dentry)
{
	char *name, *xattr_list = NULL, *smack_buf;
	int value_len, xattr_list_len;

	if (!test_share_config_flag(work->tcon->share_conf,
				    CIFSD_SHARE_FLAG_INHERIT_SMACK))
		return;

	xattr_list_len = cifsd_vfs_listxattr(dir_dentry, &xattr_list);
	if (xattr_list_len < 0) {
		goto out;
	} else if (!xattr_list_len) {
		cifsd_err("no ea data in the file\n");
		return;
	}

	for (name = xattr_list; name - xattr_list < xattr_list_len;
			name += strlen(name) + 1) {
		int rc;

		cifsd_debug("%s, len %zd\n", name, strlen(name));
		if (strcmp(name, XATTR_NAME_SMACK))
			continue;

		value_len = cifsd_vfs_getxattr(dir_dentry, name, &smack_buf);
		if (value_len <= 0)
			continue;

		rc = cifsd_vfs_setxattr(dentry, XATTR_NAME_SMACK, smack_buf,
					value_len, 0);
		cifsd_free(smack_buf);
		if (rc < 0)
			cifsd_err("cifsd_vfs_setxattr() failed: %d\n", rc);
	}
out:
	cifsd_vfs_xattr_free(xattr_list);
}

/**
 * cifsd_vfs_create() - vfs helper for smb create file
 * @work:	work
 * @name:	file name
 * @mode:	file create mode
 *
 * Return:	0 on success, otherwise error
 */
int cifsd_vfs_create(struct cifsd_work *work,
		     const char *name,
		     umode_t mode)
{
	struct path path;
	struct dentry *dentry;
	int err;

	dentry = kern_path_create(AT_FDCWD, name, &path, 0);
	if (IS_ERR(dentry)) {
		err = PTR_ERR(dentry);
		if (err != -ENOENT)
			cifsd_err("path create failed for %s, err %d\n",
				name, err);
		return err;
	}

	mode |= S_IFREG;
	err = vfs_create(d_inode(path.dentry), dentry, mode, true);
	if (!err) {
		cifsd_vfs_inode_uid_gid(work, d_inode(dentry));
		cifsd_vfs_inherit_owner(work, d_inode(path.dentry),
			d_inode(dentry));
		cifsd_vfs_inherit_smack(work, path.dentry, dentry);
	}
	else
		cifsd_err("File(%s): creation failed (err:%d)\n", name, err);

	done_path_create(&path, dentry);
	return err;
}

/**
 * cifsd_vfs_mkdir() - vfs helper for smb create directory
 * @work:	work
 * @name:	directory name
 * @mode:	directory create mode
 *
 * Return:	0 on success, otherwise error
 */
int cifsd_vfs_mkdir(struct cifsd_work *work,
		    const char *name,
		    umode_t mode)
{
	struct path path;
	struct dentry *dentry;
	int err;

	dentry = kern_path_create(AT_FDCWD, name, &path, LOOKUP_DIRECTORY);
	if (IS_ERR(dentry)) {
		err = PTR_ERR(dentry);
		if (err != -EEXIST)
			cifsd_err("path create failed for %s, err %d\n",
					name, err);
		return err;
	}

	mode |= S_IFDIR;
	err = vfs_mkdir(d_inode(path.dentry), dentry, mode);
	if (!err) {
		cifsd_vfs_inode_uid_gid(work, d_inode(dentry));
		cifsd_vfs_inherit_owner(work, d_inode(path.dentry),
			d_inode(dentry));
		cifsd_vfs_inherit_smack(work, path.dentry, dentry);
	} else
		cifsd_err("mkdir(%s): creation failed (err:%d)\n", name, err);

	done_path_create(&path, dentry);
	return err;
}

static ssize_t cifsd_vfs_getcasexattr(struct dentry *dentry,
				      char *attr_name,
				      int attr_name_len,
				      char **attr_value)
{
	char *name, *xattr_list = NULL;
	ssize_t value_len = -ENOENT, xattr_list_len;

	xattr_list_len = cifsd_vfs_listxattr(dentry, &xattr_list);
	if (xattr_list_len <= 0)
		goto out;

	for (name = xattr_list; name - xattr_list < xattr_list_len;
			name += strlen(name) + 1) {
		cifsd_debug("%s, len %zd\n", name, strlen(name));
		if (strncasecmp(attr_name, name, attr_name_len))
			continue;

		value_len = cifsd_vfs_getxattr(dentry,
					       name,
					       attr_value);
		if (value_len < 0)
			cifsd_err("failed to get xattr in file\n");
		break;
	}

out:
	cifsd_vfs_xattr_free(xattr_list);
	return value_len;
}

static int cifsd_vfs_stream_read(struct cifsd_file *fp, char *buf, loff_t *pos,
	size_t count)
{
	ssize_t v_len;
	char *stream_buf = NULL;
	int err;

	cifsd_debug("read stream data pos : %llu, count : %zd\n",
			*pos, count);

	v_len = cifsd_vfs_getcasexattr(fp->filp->f_path.dentry,
				       fp->stream.name,
				       fp->stream.size,
				       &stream_buf);
	if (v_len == -ENOENT) {
		cifsd_err("not found stream in xattr : %zd\n", v_len);
		err = -ENOENT;
		return err;
	}

	memcpy(buf, &stream_buf[*pos], count);
	return v_len > count ? count : v_len;
}

/**
 * check_lock_range() - vfs helper for smb byte range file locking
 * @filp:	the file to apply the lock to
 * @start:	lock start byte offset
 * @end:	lock end byte offset
 * @type:	byte range type read/write
 *
 * Return:	0 on success, otherwise error
 */
static int check_lock_range(struct file *filp,
			    loff_t start,
			    loff_t end,
			    unsigned char type)
{
	struct file_lock *flock;
	struct file_lock_context *ctx = file_inode(filp)->i_flctx;
	int error = 0;

	if (!ctx || list_empty_careful(&ctx->flc_posix))
		return 0;

	spin_lock(&ctx->flc_lock);
	list_for_each_entry(flock, &ctx->flc_posix, fl_list) {
		if (filp == flock->fl_owner)
			continue;
		/* check conflict locks */
		if (flock->fl_end >= start && end >= flock->fl_start) {
			if (flock->fl_type == F_RDLCK) {
				if (type == WRITE) {
					cifsd_err("not allow write by shared lock\n");
					error = 1;
					goto out;
				}
			} else if (flock->fl_type == F_WRLCK) {
				/* check owner in lock */
				if (flock->fl_file != filp) {
					error = 1;
					cifsd_err("not allow rw access by exclusive lock from other opens\n");
					goto out;
				}
			}
		}
	}
out:
	spin_unlock(&ctx->flc_lock);
	return error;
}

/**
 * cifsd_vfs_read() - vfs helper for smb file read
 * @work:	smb work
 * @fid:	file id of open file
 * @count:	read byte count
 * @pos:	file pos
 *
 * Return:	number of read bytes on success, otherwise error
 */
int cifsd_vfs_read(struct cifsd_work *work,
		 struct cifsd_file *fp,
		 size_t count,
		 loff_t *pos)
{
	struct file *filp;
	ssize_t nbytes = 0;
	char *rbuf, *name;
	struct inode *inode;
	char namebuf[NAME_MAX];
	int ret;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
	mm_segment_t old_fs;
#endif

	rbuf = AUX_PAYLOAD(work);
	filp = fp->filp;
	inode = d_inode(filp->f_path.dentry);
	if (S_ISDIR(inode->i_mode))
		return -EISDIR;

	if (unlikely(count == 0))
		return 0;

	if (work->conn->connection_type) {
		if (!(fp->daccess & (FILE_READ_DATA_LE |
		    FILE_GENERIC_READ_LE | FILE_MAXIMAL_ACCESS_LE |
		    FILE_GENERIC_ALL_LE | FILE_EXECUTE_LE))) {
			cifsd_err("no right to read(%s)\n", FP_FILENAME(fp));
			return -EACCES;
		}
	}

	if (cifsd_stream_fd(fp))
		return cifsd_vfs_stream_read(fp, rbuf, pos, count);

	ret = check_lock_range(filp, *pos, *pos + count - 1,
			READ);
	if (ret) {
		cifsd_err("unable to read due to lock\n");
		return -EAGAIN;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
	old_fs = get_fs();
	set_fs(KERNEL_DS);

	nbytes = vfs_read(filp, rbuf, count, pos);
	set_fs(old_fs);
#else
	nbytes = kernel_read(filp, rbuf, count, pos);
#endif
	if (nbytes < 0) {
		name = d_path(&filp->f_path, namebuf, sizeof(namebuf));
		if (IS_ERR(name))
			name = "(error)";
		cifsd_err("smb read failed for (%s), err = %zd\n",
				name, nbytes);
		return nbytes;
	}

	filp->f_pos = *pos;
	return nbytes;
}

static int cifsd_vfs_stream_write(struct cifsd_file *fp, char *buf, loff_t *pos,
	size_t count)
{
	char *stream_buf = NULL, *wbuf;
	size_t size, v_len;
	int err = 0;

	cifsd_debug("write stream data pos : %llu, count : %zd\n",
			*pos, count);

	size = *pos + count;
	if (size > XATTR_SIZE_MAX) {
		size = XATTR_SIZE_MAX;
		count = (*pos + count) - XATTR_SIZE_MAX;
	}

	v_len = cifsd_vfs_getcasexattr(fp->filp->f_path.dentry,
				       fp->stream.name,
				       fp->stream.size,
				       &stream_buf);
	if (v_len == -ENOENT) {
		cifsd_err("not found stream in xattr : %zd\n", v_len);
		err = -ENOENT;
		goto out;
	}

	if (v_len < size) {
		wbuf = cifsd_alloc(size);
		if (!wbuf) {
			err = -ENOMEM;
			goto out;
		}

		if (v_len > 0)
			memcpy(wbuf, stream_buf, v_len);
		stream_buf = wbuf;
	}

	memcpy(&stream_buf[*pos], buf, count);

	err = cifsd_vfs_setxattr(fp->filp->f_path.dentry,
				 fp->stream.name,
				 (void *)stream_buf,
				 size,
				 0);
	if (err < 0)
		goto out;

	fp->filp->f_pos = *pos;
	err = 0;
out:
	cifsd_free(stream_buf);
	return err;
}

/**
 * cifsd_vfs_write() - vfs helper for smb file write
 * @work:	work
 * @fid:	file id of open file
 * @buf:	buf containing data for writing
 * @count:	read byte count
 * @pos:	file pos
 * @sync:	fsync after write
 * @written:	number of bytes written
 *
 * Return:	0 on success, otherwise error
 */
int cifsd_vfs_write(struct cifsd_work *work, struct cifsd_file *fp,
	char *buf, size_t count, loff_t *pos, bool sync, ssize_t *written)
{
	struct cifsd_session *sess = work->sess;
	struct file *filp;
	loff_t	offset = *pos;
	int err = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
	mm_segment_t old_fs;
#endif

	if (sess->conn->connection_type) {
		if (!(fp->daccess & (FILE_WRITE_DATA_LE |
		   FILE_GENERIC_WRITE_LE | FILE_MAXIMAL_ACCESS_LE |
		   FILE_GENERIC_ALL_LE))) {
			cifsd_err("no right to write(%s)\n", FP_FILENAME(fp));
			err = -EACCES;
			goto out;
		}
	}

	filp = fp->filp;

	if (cifsd_stream_fd(fp)) {
		err = cifsd_vfs_stream_write(fp, buf, pos, count);
		if (!err)
			*written = count;
		goto out;
	}

	err = check_lock_range(filp, *pos, *pos + count - 1, WRITE);
	if (err) {
		cifsd_err("unable to write due to lock\n");
		err = -EAGAIN;
		goto out;
	}

	/* Do we need to break any of a levelII oplock? */
	smb_break_all_levII_oplock(work, fp, 1);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	err = vfs_write(filp, buf, count, pos);
	set_fs(old_fs);
#else
	err = kernel_write(filp, buf, count, pos);
#endif

	if (err < 0) {
		cifsd_debug("smb write failed, err = %d\n", err);
		goto out;
	}

	filp->f_pos = *pos;
	*written = err;
	err = 0;
	if (sync) {
		err = vfs_fsync_range(filp, offset, offset + *written, 0);
		if (err < 0)
			cifsd_err("fsync failed for filename = %s, err = %d\n",
					FP_FILENAME(fp), err);
	}

out:
	return err;
}

static void __fill_dentry_attributes(struct cifsd_work *work,
				     struct dentry *dentry,
				     struct cifsd_kstat *cifsd_kstat)
{
	/*
	 * set default value for the case that store dos attributes is not yes
	 * or that acl is disable in server's filesystem and the config is yes.
	 */
	if (S_ISDIR(cifsd_kstat->kstat->mode))
		cifsd_kstat->file_attributes = FILE_ATTRIBUTE_DIRECTORY_LE;
	else
		cifsd_kstat->file_attributes = FILE_ATTRIBUTE_ARCHIVE_LE;

	if (test_share_config_flag(work->tcon->share_conf,
				   CIFSD_SHARE_FLAG_STORE_DOS_ATTRS)) {
		char *file_attribute = NULL;
		int rc;

		rc = cifsd_vfs_getxattr(dentry,
					XATTR_NAME_FILE_ATTRIBUTE,
					&file_attribute);
		if (rc > 0)
			cifsd_kstat->file_attributes =
				*((__le32 *)file_attribute);
		else
			cifsd_debug("fail to fill file attributes.\n");
		cifsd_free(file_attribute);
	}
}

static void __file_dentry_ctime(struct cifsd_work *work,
				struct dentry *dentry,
				struct cifsd_kstat *cifsd_kstat)
{
	char *create_time = NULL;
	int xattr_len;
	u64 time;

	/*
	 * if "store dos attributes" conf is not yes,
	 * create time = change time
	 */
	time = cifs_UnixTimeToNT(from_kern_timespec(cifsd_kstat->kstat->ctime));
	cifsd_kstat->create_time = time;

	if (test_share_config_flag(work->tcon->share_conf,
				   CIFSD_SHARE_FLAG_STORE_DOS_ATTRS)) {
		xattr_len = cifsd_vfs_getxattr(dentry,
					       XATTR_NAME_CREATION_TIME,
					       &create_time);
		if (xattr_len > 0)
			cifsd_kstat->create_time = *((u64 *)create_time);
		cifsd_free(create_time);
	}
}

#ifdef CONFIG_CIFS_INSECURE_SERVER
/**
 * smb_check_attrs() - sanitize inode attributes
 * @inode:	inode
 * @attrs:	inode attributes
 */
static void smb_check_attrs(struct inode *inode, struct iattr *attrs)
{
	/* sanitize the mode change */
	if (attrs->ia_valid & ATTR_MODE) {
		attrs->ia_mode &= S_IALLUGO;
		attrs->ia_mode |= (inode->i_mode & ~S_IALLUGO);
	}

	/* Revoke setuid/setgid on chown */
	if (!S_ISDIR(inode->i_mode) &&
		(((attrs->ia_valid & ATTR_UID) &&
				!uid_eq(attrs->ia_uid, inode->i_uid)) ||
		 ((attrs->ia_valid & ATTR_GID) &&
				!gid_eq(attrs->ia_gid, inode->i_gid)))) {
		attrs->ia_valid |= ATTR_KILL_PRIV;
		if (attrs->ia_valid & ATTR_MODE) {
			/* we're setting mode too, just clear the s*id bits */
			attrs->ia_mode &= ~S_ISUID;
			if (attrs->ia_mode & 0010)
				attrs->ia_mode &= ~S_ISGID;
		} else {
			/* set ATTR_KILL_* bits and let VFS handle it */
			attrs->ia_valid |= (ATTR_KILL_SUID | ATTR_KILL_SGID);
		}
	}
}

/**
 * cifsd_vfs_setattr() - vfs helper for smb setattr
 * @work:	work
 * @name:	file name
 * @fid:	file id of open file
 * @attrs:	inode attributes
 *
 * Return:	0 on success, otherwise error
 */
int cifsd_vfs_setattr(struct cifsd_work *work, const char *name,
		uint64_t fid, struct iattr *attrs)
{
	struct file *filp;
	struct dentry *dentry;
	struct inode *inode;
	struct path path;
	bool update_size = false;
	int err = 0;
	struct cifsd_file *fp = NULL;

	if (name) {
		err = kern_path(name, 0, &path);
		if (err) {
			cifsd_debug("lookup failed for %s, err = %d\n",
					name, err);
			return -ENOENT;
		}
		dentry = path.dentry;
		inode = d_inode(dentry);
	} else {

		fp = cifsd_lookup_fd_fast(work, fid);
		if (!fp) {
			cifsd_err("failed to get filp for fid %llu\n", fid);
			return -ENOENT;
		}

		filp = fp->filp;
		dentry = filp->f_path.dentry;
		inode = d_inode(dentry);
	}

	/* no need to update mode of symlink */
	if (S_ISLNK(inode->i_mode))
		attrs->ia_valid &= ~ATTR_MODE;

	/* skip setattr, if nothing to update */
	if (!attrs->ia_valid) {
		err = 0;
		goto out;
	}

	smb_check_attrs(inode, attrs);
	if (attrs->ia_valid & ATTR_SIZE) {
		err = get_write_access(inode);
		if (err)
			goto out;

		err = locks_verify_truncate(inode, NULL, attrs->ia_size);
		if (err) {
			put_write_access(inode);
			goto out;
		}
		update_size = true;
	}

	attrs->ia_valid |= ATTR_CTIME;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
	inode_lock(inode);
	err = notify_change(dentry, attrs, NULL);
	inode_unlock(inode);
#else
	mutex_lock(&inode->i_mutex);
	err = notify_change(dentry, attrs, NULL);
	mutex_unlock(&inode->i_mutex);
#endif

	if (update_size)
		put_write_access(inode);

	if (!err) {
		sync_inode_metadata(inode, 1);
		cifsd_debug("fid %llu, setattr done\n", fid);
	}

out:
	if (name)
		path_put(&path);
	cifsd_fd_put(work, fp);
	return err;
}

/**
 * cifsd_vfs_getattr() - vfs helper for smb getattr
 * @work:	work
 * @fid:	file id of open file
 * @attrs:	inode attributes
 *
 * Return:	0 on success, otherwise error
 */
int cifsd_vfs_getattr(struct cifsd_work *work, uint64_t fid,
		struct kstat *stat)
{
	struct file *filp;
	struct cifsd_file *fp;
	int err;

	fp = cifsd_lookup_fd_fast(work, fid);
	if (!fp) {
		cifsd_err("failed to get filp for fid %llu\n", fid);
		return -ENOENT;
	}

	filp = fp->filp;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
	err = vfs_getattr(&filp->f_path, stat, STATX_BASIC_STATS,
		AT_STATX_SYNC_AS_STAT);
#else
	err = vfs_getattr(&filp->f_path, stat);
#endif
	if (err)
		cifsd_err("getattr failed for fid %llu, err %d\n", fid, err);
	cifsd_fd_put(work, fp);
	return err;
}

/**
 * cifsd_vfs_symlink() - vfs helper for creating smb symlink
 * @name:	source file name
 * @symname:	symlink name
 *
 * Return:	0 on success, otherwise error
 */
int cifsd_vfs_symlink(const char *name, const char *symname)
{
	struct path path;
	struct dentry *dentry;
	int err;

	dentry = kern_path_create(AT_FDCWD, symname, &path, 0);
	if (IS_ERR(dentry)) {
		err = PTR_ERR(dentry);
		cifsd_err("path create failed for %s, err %d\n", name, err);
		return err;
	}

	err = vfs_symlink(d_inode(dentry->d_parent), dentry, name);
	if (err && (err != -EEXIST || err != -ENOSPC))
		cifsd_debug("failed to create symlink, err %d\n", err);

	done_path_create(&path, dentry);

	return err;
}

/**
 * cifsd_vfs_readlink() - vfs helper for reading value of symlink
 * @path:	path of symlink
 * @buf:	destination buffer for symlink value
 * @lenp:	destination buffer length
 *
 * Return:	symlink value length on success, otherwise error
 */
int cifsd_vfs_readlink(struct path *path, char *buf, int lenp)
{
	struct inode *inode;
	mm_segment_t old_fs;
	int err;

	if (!path)
		return -ENOENT;

	inode = d_inode(path->dentry);
	if (!S_ISLNK(inode->i_mode))
		return -EINVAL;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	err = inode->i_op->readlink(path->dentry, (char __user *)buf, lenp);
	set_fs(old_fs);
	if (err < 0)
		cifsd_err("readlink failed, err = %d\n", err);

	return err;
}

static void fill_file_attributes(struct cifsd_work *work,
				 struct path *path,
				 struct cifsd_kstat *cifsd_kstat)
{
	__fill_dentry_attributes(work, path->dentry, cifsd_kstat);
}

static void fill_create_time(struct cifsd_work *work,
			     struct path *path,
			     struct cifsd_kstat *cifsd_kstat)
{
	__file_dentry_ctime(work, path->dentry, cifsd_kstat);
}

int cifsd_vfs_readdir_name(struct cifsd_work *work,
			   struct cifsd_kstat *cifsd_kstat,
			   const char *de_name,
			   int de_name_len,
			   const char *dir_path)
{
	struct path path;
	int rc, file_pathlen, dir_pathlen;
	char *name;

	dir_pathlen = strlen(dir_path);
	/* 1 for '/'*/
	file_pathlen = dir_pathlen +  de_name_len + 1;
	name = kmalloc(file_pathlen + 1, GFP_KERNEL);
	if (!name)
		return -ENOMEM;

	memcpy(name, dir_path, dir_pathlen);
	memset(name + dir_pathlen, '/', 1);
	memcpy(name + dir_pathlen + 1, de_name, de_name_len);
	name[file_pathlen] = '\0';

	rc = cifsd_vfs_kern_path(name, LOOKUP_FOLLOW, &path, 1);
	if (rc) {
		cifsd_err("lookup failed: %s [%d]\n", name, rc);
		kfree(name);
		return -ENOMEM;
	}

	generic_fillattr(d_inode(path.dentry), cifsd_kstat->kstat);
	fill_create_time(work, &path, cifsd_kstat);
	fill_file_attributes(work, &path, cifsd_kstat);
	path_put(&path);
	kfree(name);
	return 0;
}
#else
static inline void smb_check_attrs(struct inode *inode, struct iattr *attrs)
{
}

int cifsd_vfs_setattr(struct cifsd_work *work, const char *name,
		      uint64_t fid, struct iattr *attrs)
{
	return -ENOTSUPP;
}

int cifsd_vfs_getattr(struct cifsd_work *work, uint64_t fid,
		      struct kstat *stat)
{
	return -ENOTSUPP;
}

int cifsd_vfs_symlink(const char *name, const char *symname)
{
	return -ENOTSUPP;
}

int cifsd_vfs_readlink(struct path *path, char *buf, int lenp)
{
	return -ENOTSUPP;
}

int cifsd_vfs_readdir_name(struct cifsd_work *work,
			   struct cifsd_kstat *cifsd_kstat,
			   const char *de_name,
			   int de_name_len,
			   const char *dir_path)
{
	return 0;
}
#endif

/**
 * cifsd_vfs_fsync() - vfs helper for smb fsync
 * @work:	work
 * @fid:	file id of open file
 *
 * Return:	0 on success, otherwise error
 */
int cifsd_vfs_fsync(struct cifsd_work *work, uint64_t fid, uint64_t p_id)
{
	struct cifsd_file *fp;
	int err;

	fp = cifsd_lookup_fd_slow(work, fid, p_id);
	if (!fp) {
		cifsd_err("failed to get filp for fid %llu\n", fid);
		return -ENOENT;
	}
	err = vfs_fsync(fp->filp, 0);
	if (err < 0)
		cifsd_err("smb fsync failed, err = %d\n", err);
	cifsd_fd_put(work, fp);
	return err;
}

/**
 * cifsd_vfs_remove_file() - vfs helper for smb rmdir or unlink
 * @name:	absolute directory or file name
 *
 * Return:	0 on success, otherwise error
 */
int cifsd_vfs_remove_file(char *name)
{
	struct path parent;
	struct dentry *dir, *dentry;
	char *last;
	int err = -ENOENT;

	last = extract_last_component(name);
	if (!last)
		return -ENOENT;

	err = kern_path(name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &parent);
	if (err) {
		cifsd_debug("can't get %s, err %d\n", name, err);
		roolback_path_modification(last);
		return err;
	}

	dir = parent.dentry;
	if (!d_inode(dir))
		goto out;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
	inode_lock_nested(d_inode(dir), I_MUTEX_PARENT);
#else
	mutex_lock_nested(&d_inode(dir)->i_mutex, I_MUTEX_PARENT);
#endif
	dentry = lookup_one_len(last, dir, strlen(last));
	if (IS_ERR(dentry)) {
		err = PTR_ERR(dentry);
		cifsd_debug("%s: lookup failed, err %d\n", last, err);
		goto out_err;
	}

	if (!d_inode(dentry) || !d_inode(dentry)->i_nlink) {
		dput(dentry);
		err = -ENOENT;
		goto out_err;
	}

	if (S_ISDIR(d_inode(dentry)->i_mode)) {
		err = vfs_rmdir(d_inode(dir), dentry);
		if (err && err != -ENOTEMPTY)
			cifsd_debug("%s: rmdir failed, err %d\n", name, err);
	} else {
		err = vfs_unlink(d_inode(dir), dentry, NULL);
		if (err)
			cifsd_debug("%s: unlink failed, err %d\n", name, err);
	}

	dput(dentry);
out_err:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
	inode_unlock(d_inode(dir));
#else
	mutex_unlock(&d_inode(dir)->i_mutex);
#endif
out:
	roolback_path_modification(last);
	path_put(&parent);
	return err;
}

/**
 * cifsd_vfs_link() - vfs helper for creating smb hardlink
 * @oldname:	source file name
 * @newname:	hardlink name
 *
 * Return:	0 on success, otherwise error
 */
int cifsd_vfs_link(const char *oldname, const char *newname)
{
	struct path oldpath, newpath;
	struct dentry *dentry;
	int err;

	err = kern_path(oldname, LOOKUP_FOLLOW, &oldpath);
	if (err) {
		cifsd_err("cannot get linux path for %s, err = %d\n",
				oldname, err);
		goto out1;
	}

	dentry = kern_path_create(AT_FDCWD, newname, &newpath,
			LOOKUP_FOLLOW | LOOKUP_REVAL);
	if (IS_ERR(dentry)) {
		err = PTR_ERR(dentry);
		cifsd_err("path create err for %s, err %d\n", newname, err);
		goto out2;
	}

	err = -EXDEV;
	if (oldpath.mnt != newpath.mnt) {
		cifsd_err("vfs_link failed err %d\n", err);
		goto out3;
	}

	err = vfs_link(oldpath.dentry, d_inode(newpath.dentry), dentry, NULL);
	if (err)
		cifsd_debug("vfs_link failed err %d\n", err);

out3:
	done_path_create(&newpath, dentry);
out2:
	path_put(&oldpath);

out1:
	return err;
}

static int __cifsd_vfs_rename(struct dentry *src_dent_parent,
			      struct dentry *src_dent,
			      struct dentry *dst_dent_parent,
			      struct dentry *trap_dent,
			      char *dst_name)
{
	struct dentry *dst_dent;
	int err;

	spin_lock(&src_dent->d_lock);
	list_for_each_entry(dst_dent, &src_dent->d_subdirs, d_child) {
		struct cifsd_file *child_fp;

		if (d_really_is_negative(dst_dent))
			continue;

		child_fp = cifsd_lookup_fd_inode(d_inode(dst_dent));
		if (child_fp) {
			spin_unlock(&src_dent->d_lock);
			cifsd_debug("Forbid rename, sub file/dir is in use\n");
			return -EACCES;
		}
	}
	spin_unlock(&src_dent->d_lock);

	if (d_really_is_negative(src_dent_parent))
		return -ENOENT;
	if (d_really_is_negative(dst_dent_parent))
		return -ENOENT;
	if (d_really_is_negative(src_dent))
		return -ENOENT;
	if (src_dent == trap_dent)
		return -EINVAL;

	dst_dent = lookup_one_len(dst_name, dst_dent_parent, strlen(dst_name));
	err = PTR_ERR(dst_dent);
	if (IS_ERR(dst_dent)) {
		cifsd_err("lookup failed %s [%d]\n", dst_name, err);
		return err;
	}

	err = -ENOTEMPTY;
	if (dst_dent != trap_dent && !d_really_is_positive(dst_dent)) {
		err = vfs_rename(d_inode(src_dent_parent),
				 src_dent,
				 d_inode(dst_dent_parent),
				 dst_dent,
				 NULL,
				 0);
	}
	if (err)
		cifsd_err("vfs_rename failed err %d\n", err);
	if (dst_dent)
		dput(dst_dent);
	return err;
}

int cifsd_vfs_fp_rename(struct cifsd_file *fp, char *newname)
{
	struct path dst_path;
	struct dentry *src_dent_parent, *dst_dent_parent;
	struct dentry *src_dent, *trap_dent;
	char *dst_name;
	int err;

	dst_name = extract_last_component(newname);
	if (!dst_name)
		return -EINVAL;

	src_dent_parent = dget_parent(fp->filp->f_path.dentry);
	if (!src_dent_parent)
		return -EINVAL;

	src_dent = fp->filp->f_path.dentry;
	dget(src_dent);

	err = kern_path(newname, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &dst_path);
	if (err) {
		cifsd_err("Cannot get path for %s [%d]\n", newname, err);
		goto out;
	}
	dst_dent_parent = dst_path.dentry;
	dget(dst_dent_parent);

	trap_dent = lock_rename(src_dent_parent, dst_dent_parent);
	err = __cifsd_vfs_rename(src_dent_parent,
				 src_dent,
				 dst_dent_parent,
				 trap_dent,
				 dst_name);
	unlock_rename(src_dent_parent, dst_dent_parent);
	dput(dst_dent_parent);
	path_put(&dst_path);
out:
	dput(src_dent);
	dput(src_dent_parent);
	return err;
}

#ifdef CONFIG_CIFS_INSECURE_SERVER
int cifsd_vfs_rename_slowpath(char *oldname, char *newname)
{
	struct path dst_path, src_path;
	struct dentry *src_dent_parent, *dst_dent_parent;
	struct dentry *src_dent = NULL, *trap_dent;
	char *src_name, *dst_name;
	int err;

	src_name = extract_last_component(oldname);
	if (!src_name)
		return -EINVAL;
	dst_name = extract_last_component(newname);
	if (!dst_name)
		return -EINVAL;

	err = kern_path(oldname, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &src_path);
	if (err) {
		cifsd_err("Cannot get path for %s [%d]\n", oldname, err);
		return err;
	}
	src_dent_parent = src_path.dentry;
	dget(src_dent_parent);

	err = kern_path(newname, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &dst_path);
	if (err) {
		cifsd_err("Cannot get path for %s [%d]\n", newname, err);
		dput(src_dent_parent);
		path_put(&src_path);
		return err;
	}
	dst_dent_parent = dst_path.dentry;
	dget(dst_dent_parent);

	trap_dent = lock_rename(src_dent_parent, dst_dent_parent);
	src_dent = lookup_one_len(src_name, src_dent_parent, strlen(src_name));
	err = PTR_ERR(src_dent);
	if (IS_ERR(src_dent)) {
		src_dent = NULL;
		cifsd_err("%s lookup failed with error = %d\n", src_name, err);
		goto out;
	}

	err = __cifsd_vfs_rename(src_dent_parent,
				 src_dent,
				 dst_dent_parent,
				 trap_dent,
				 dst_name);
out:
	if (src_dent)
		dput(src_dent);
	dput(dst_dent_parent);
	dput(src_dent_parent);
	unlock_rename(src_dent_parent, dst_dent_parent);
	path_put(&src_path);
	path_put(&dst_path);
	return err;
}
#else
int cifsd_vfs_rename_slowpath(char *oldname, char *newname)
{
	return 0;
}
#endif

/**
 * cifsd_vfs_truncate() - vfs helper for smb file truncate
 * @work:	work
 * @name:	old filename
 * @fid:	file id of old file
 * @size:	truncate to given size
 *
 * Return:	0 on success, otherwise error
 */
int cifsd_vfs_truncate(struct cifsd_work *work, const char *name,
	struct cifsd_file *fp, loff_t size)
{
	struct path path;
	int err = 0;
	struct inode *inode;

	if (name) {
		err = kern_path(name, 0, &path);
		if (err) {
			cifsd_err("cannot get linux path for %s, err %d\n",
					name, err);
			return err;
		}
		err = vfs_truncate(&path, size);
		if (err)
			cifsd_err("truncate failed for %s err %d\n",
					name, err);
		path_put(&path);
	} else {
		struct file *filp;

		filp = fp->filp;

		/* Do we need to break any of a levelII oplock? */
		smb_break_all_levII_oplock(work, fp, 1);

		inode = file_inode(filp);
		if (size < inode->i_size) {
			err = check_lock_range(filp, size,
					inode->i_size - 1, WRITE);
		} else {
			err = check_lock_range(filp, inode->i_size,
					size - 1, WRITE);
		}

		if (err) {
			cifsd_err("failed due to lock\n");
			return -EAGAIN;
		}

		err = vfs_truncate(&filp->f_path, size);
		if (err)
			cifsd_err("truncate failed for filename : %s err %d\n",
					fp->filename, err);
	}

	return err;
}

/**
 * cifsd_vfs_listxattr() - vfs helper for smb list extended attributes
 * @dentry:	dentry of file for listing xattrs
 * @list:	destination buffer
 * @size:	destination buffer length
 *
 * Return:	xattr list length on success, otherwise error
 */
ssize_t cifsd_vfs_listxattr(struct dentry *dentry, char **list)
{
	ssize_t size;
	char *vlist = NULL;

	size = vfs_listxattr(dentry, NULL, 0);
	if (size <= 0)
		return size;

	vlist = cifsd_alloc(size);
	if (!vlist)
		return -ENOMEM;

	*list = vlist;
	size = vfs_listxattr(dentry, vlist, size);
	if (size < 0) {
		cifsd_debug("listxattr failed\n");
		cifsd_vfs_xattr_free(vlist);
		*list = NULL;
	}

	return size;
}

static ssize_t cifsd_vfs_xattr_len(struct dentry *dentry,
			   char *xattr_name)
{
	return vfs_getxattr(dentry, xattr_name, NULL, 0);
}

/**
 * cifsd_vfs_getxattr() - vfs helper for smb get extended attributes value
 * @dentry:	dentry of file for getting xattrs
 * @xattr_name:	name of xattr name to query
 * @xattr_buf:	destination buffer xattr value
 *
 * Return:	read xattr value length on success, otherwise error
 */
ssize_t cifsd_vfs_getxattr(struct dentry *dentry,
			   char *xattr_name,
			   char **xattr_buf)
{
	ssize_t xattr_len;
	char *buf;

	xattr_len = cifsd_vfs_xattr_len(dentry, xattr_name);
	if (xattr_len < 0)
		return xattr_len;

	buf = kmalloc(xattr_len + 1, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	xattr_len = vfs_getxattr(dentry, xattr_name, (void *)buf, xattr_len);
	if (xattr_len)
		*xattr_buf = buf;
	return xattr_len;
}

/**
 * cifsd_vfs_setxattr() - vfs helper for smb set extended attributes value
 * @dentry:	dentry to set XATTR at
 * @name:	xattr name for setxattr
 * @value:	xattr value to set
 * @size:	size of xattr value
 * @flags:	destination buffer length
 *
 * Return:	0 on success, otherwise error
 */
int cifsd_vfs_setxattr(struct dentry *dentry,
		       const char *attr_name,
		       const void *attr_value,
		       size_t attr_size,
		       int flags)
{
	int err;

	err = vfs_setxattr(dentry,
			   attr_name,
			   attr_value,
			   attr_size,
			   flags);
	if (err)
		cifsd_debug("setxattr failed, err %d\n", err);
	return err;
}

#ifdef CONFIG_CIFS_INSECURE_SERVER
int cifsd_vfs_fsetxattr(const char *filename,
			const char *attr_name,
			const void *attr_value,
			size_t attr_size,
			int flags)
{
	struct path path;
	int err;

	err = kern_path(filename, 0, &path);
	if (err) {
		cifsd_debug("cannot get linux path %s, err %d\n",
				filename, err);
		return err;
	}
	err = vfs_setxattr(path.dentry,
			   attr_name,
			   attr_value,
			   attr_size,
			   flags);
	if (err)
		cifsd_debug("setxattr failed, err %d\n", err);
	path_put(&path);
	return err;
}
#else
int cifsd_vfs_fsetxattr(const char *filename,
			const char *attr_name,
			const void *attr_value,
			size_t attr_size,
			int flags)
{
	return -ENOTSUPP;
}
#endif

int cifsd_vfs_truncate_xattr(struct dentry *dentry, int wo_streams)
{
	char *name, *xattr_list = NULL;
	ssize_t xattr_list_len;
	int err = 0;

	xattr_list_len = cifsd_vfs_listxattr(dentry, &xattr_list);
	if (xattr_list_len < 0) {
		goto out;
	} else if (!xattr_list_len) {
		cifsd_debug("empty xattr in the file\n");
		goto out;
	}

	for (name = xattr_list; name - xattr_list < xattr_list_len;
			name += strlen(name) + 1) {
		cifsd_debug("%s, len %zd\n", name, strlen(name));

		if (wo_streams && !strncmp(&name[XATTR_USER_PREFIX_LEN],
			STREAM_PREFIX, STREAM_PREFIX_LEN))
			continue;

		err = vfs_removexattr(dentry, name);
		if (err)
			cifsd_debug("remove xattr failed : %s\n", name);
	}
out:
	cifsd_vfs_xattr_free(xattr_list);
	return err;
}

/**
 * cifsd_vfs_set_fadvise() - convert smb IO caching options to linux options
 * @filp:	file pointer for IO
 * @options:	smb IO options
 */
void cifsd_vfs_set_fadvise(struct file *filp, __le32 option)
{
	struct address_space *mapping;

	mapping = filp->f_mapping;

	if (!option || !mapping)
		return;

	if (option & FILE_WRITE_THROUGH_LE)
		filp->f_flags |= O_SYNC;
/*
	 * TODO : need to add special handling for Direct I/O.
	 * Direct I/O relies on MM Context of the "current" process
	 * to retrieve the pages corresponding to the user address
	 * do_direct_IO()->dio_get_page()->
				dio_refill_pages()->get_user_pages_fast()
	 * struct mm_struct *mm = current->mm;
	 * All work items in CIFSD are handled through default "kworker"
	 * - which do not have any MM Context.
	 * To handle Direct I/O will need to create another thread
	 * in kernel with MM context and redirect all direct I/O calls to
	 * thread. Since, this is Server and direct I/O not bottleneck.
	 * So, making default READ path to be buffered in all sequences
	 * (clearing direct IO flag).
	else if (option & FILE_NO_INTERMEDIATE_BUFFERING_LE &&
		 filp->f_mapping->a_ops->direct_IO)
		filp->f_flags |= O_DIRECT;
*/
	else if (option & FILE_SEQUENTIAL_ONLY_LE) {
		filp->f_ra.ra_pages = inode_to_bdi(mapping->host)->ra_pages * 2;
		spin_lock(&filp->f_lock);
		filp->f_mode &= ~FMODE_RANDOM;
		spin_unlock(&filp->f_lock);
	} else if (option & FILE_RANDOM_ACCESS_LE) {
		spin_lock(&filp->f_lock);
		filp->f_mode |= FMODE_RANDOM;
		spin_unlock(&filp->f_lock);
	}
}

/**
 * cifsd_vfs_lock() - vfs helper for smb file locking
 * @filp:	the file to apply the lock to
 * @cmd:	type of locking operation (F_SETLK, F_GETLK, etc.)
 * @flock:	The lock to be applied
 *
 * Return:	0 on success, otherwise error
 */
int cifsd_vfs_lock(struct file *filp, int cmd,
			struct file_lock *flock)
{
	cifsd_debug("calling vfs_lock_file\n");
	return vfs_lock_file(filp, cmd, flock, NULL);
}

int cifsd_vfs_readdir(struct file *file, struct cifsd_readdir_data *rdata)
{
	return iterate_dir(file, &rdata->ctx);
}

int cifsd_vfs_alloc_size(struct cifsd_work *work,
			 struct cifsd_file *fp,
			 loff_t len)
{
	smb_break_all_levII_oplock(work, fp, 1);
	return vfs_fallocate(fp->filp, FALLOC_FL_KEEP_SIZE, 0, len);
}

int cifsd_vfs_zero_data(struct cifsd_work *work,
			 struct cifsd_file *fp,
			 loff_t off,
			 loff_t len)
{
	smb_break_all_levII_oplock(work, fp, 1);
	return vfs_fallocate(fp->filp, FALLOC_FL_ZERO_RANGE, off, len);
}

int cifsd_vfs_fiemap(struct cifsd_file *fp, u64 start, u64 length,
	u64 *out_start, u64 *out_length)
{
	struct inode *inode = FP_INODE(fp);
	struct super_block *sb = inode->i_sb;
	struct fiemap_extent_info fieinfo = { 0, };
	u64 maxbytes = (u64) sb->s_maxbytes;
	int ret;

	if (!inode->i_op->fiemap)
		return -EOPNOTSUPP;

	if (start > maxbytes)
		return -EFBIG;

	fieinfo.fi_extents_start = kzalloc(sizeof(struct fiemap_extent),
		GFP_KERNEL);
	if (!fieinfo.fi_extents_start)
		return -ENOMEM;

	/*
	 * Shrink request scope to what the fs can actually handle.
	 */
	if (length > maxbytes || (maxbytes - length) < start)
		length = maxbytes - start;

	fieinfo.fi_extents_max = 1;

	ret = inode->i_op->fiemap(inode, &fieinfo, start, length);
	if (!ret && fieinfo.fi_extents_start->fe_flags) {
		*out_start = fieinfo.fi_extents_start->fe_logical;
		*out_length = fieinfo.fi_extents_start->fe_length;
	}
	kfree(fieinfo.fi_extents_start);
	return ret;
}

int cifsd_vfs_remove_xattr(struct dentry *dentry, char *attr_name)
{
	return vfs_removexattr(dentry, attr_name);
}

void cifsd_vfs_xattr_free(char *xattr)
{
	cifsd_free(xattr);
}

int cifsd_vfs_unlink(struct dentry *dir, struct dentry *dentry)
{
	int err = 0;

	dget(dentry);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
	inode_lock_nested(d_inode(dir), I_MUTEX_PARENT);
#else
	mutex_lock_nested(&d_inode(dir)->i_mutex, I_MUTEX_PARENT);
#endif
	if (!d_inode(dentry) || !d_inode(dentry)->i_nlink) {
		err = -ENOENT;
		goto out;
	}

	if (S_ISDIR(d_inode(dentry)->i_mode))
		err = vfs_rmdir(d_inode(dir), dentry);
	else
		err = vfs_unlink(d_inode(dir), dentry, NULL);

out:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
	inode_unlock(d_inode(dir));
#else
	mutex_unlock(&d_inode(dir)->i_mutex);
#endif
	dput(dentry);
	if (err)
		cifsd_debug("failed to delete, err %d\n", err);

	return err;
}

/*
 * cifsd_vfs_get_logical_sector_size() - get logical sector size from inode
 * @inode: inode
 *
 * Return: logical sector size
 */
unsigned short cifsd_vfs_logical_sector_size(struct inode *inode)
{
	struct request_queue *q;
	unsigned short ret_val = 512;

	if (!inode->i_sb->s_bdev)
		return ret_val;

	q = inode->i_sb->s_bdev->bd_disk->queue;

	if (q && q->limits.logical_block_size)
		ret_val = q->limits.logical_block_size;

	return ret_val;
}

/*
 * cifsd_vfs_get_smb2_sector_size() - get fs sector sizes
 * @inode: inode
 * @fs_ss: fs sector size struct
 */
void cifsd_vfs_smb2_sector_size(struct inode *inode,
	struct cifsd_fs_sector_size *fs_ss)
{
	struct request_queue *q;

	fs_ss->logical_sector_size = 512;
	fs_ss->physical_sector_size = 512;
	fs_ss->optimal_io_size = 512;

	if (!inode->i_sb->s_bdev)
		return;

	q = inode->i_sb->s_bdev->bd_disk->queue;

	if (q) {
		if (q->limits.logical_block_size)
			fs_ss->logical_sector_size =
				q->limits.logical_block_size;
		if (q->limits.physical_block_size)
			fs_ss->physical_sector_size =
				q->limits.physical_block_size;
		if (q->limits.io_opt)
			fs_ss->optimal_io_size = q->limits.io_opt;
	}
}

#ifdef CONFIG_CIFS_INSECURE_SERVER
/**
 * cifsd_vfs_dentry_open() - open a dentry and provide fid for it
 * @work:	smb work ptr
 * @path:	path of dentry to be opened
 * @flags:	open flags
 * @ret_id:	fid returned on this
 * @option:	file access pattern options for fadvise
 * @fexist:	file already present or not
 *
 * Return:	0 on success, otherwise error
 */
struct cifsd_file *cifsd_vfs_dentry_open(struct cifsd_work *work,
	const struct path *path, int flags, __le32 option, int fexist)
{
	struct file *filp;
	int err = 0;
	struct cifsd_file *fp = NULL;

	filp = dentry_open(path, flags | O_LARGEFILE, current_cred());
	if (IS_ERR(filp)) {
		err = PTR_ERR(filp);
		cifsd_err("dentry open failed, err %d\n", err);
		return ERR_PTR(err);
	}

	cifsd_vfs_set_fadvise(filp, option);

	fp = cifsd_open_fd(work, filp);
	if (IS_ERR(fp)) {
		fput(filp);
		err = PTR_ERR(fp);
		cifsd_err("id insert failed\n");
		goto err_out;
	}

	if (flags & O_TRUNC) {
		if (fexist)
			smb_break_all_oplock(work, fp);
		err = vfs_truncate((struct path *)path, 0);
		if (err)
			goto err_out;
	}
	return fp;

err_out:
	if (!IS_ERR(fp))
		cifsd_close_fd(work, fp->volatile_id);
	if (err) {
		fp = ERR_PTR(err);
		cifsd_err("err : %d\n", err);
	}
	return fp;
}
#else
struct cifsd_file *cifsd_vfs_dentry_open(struct cifsd_work *work,
					 const struct path *path,
					 int flags,
					 __le32 option,
					 int fexist)
{
	return NULL;
}
#endif

static int __dir_empty(struct dir_context *ctx,
				   const char *name,
				   int namlen,
				   loff_t offset,
				   u64 ino,
				   unsigned int d_type)
{
	struct cifsd_readdir_data *buf;

	buf = container_of(ctx, struct cifsd_readdir_data, ctx);
	buf->dirent_count++;

	if (buf->dirent_count > 2)
		return -ENOTEMPTY;
	return 0;
}

/**
 * cifsd_vfs_empty_dir() - check for empty directory
 * @fp:	cifsd file pointer
 *
 * Return:	true if directory empty, otherwise false
 */
int cifsd_vfs_empty_dir(struct cifsd_file *fp)
{
	int err;

	set_ctx_actor(&fp->readdir_data.ctx, __dir_empty);
	fp->readdir_data.dirent_count	= 0;

	err = cifsd_vfs_readdir(fp->filp, &fp->readdir_data);
	if (fp->readdir_data.dirent_count > 2)
		err = -ENOTEMPTY;
	else
		err = 0;
	return err;
}

static int __caseless_lookup(struct dir_context *ctx,
			     const char *name,
			     int namlen,
			     loff_t offset,
			     u64 ino,
			     unsigned int d_type)
{
	struct cifsd_readdir_data *buf;

	buf = container_of(ctx, struct cifsd_readdir_data, ctx);

	if (buf->used != namlen)
		return 0;
	if (!strncasecmp((char *)buf->private, name, namlen)) {
		strncpy((char *)buf->private, name, namlen);
		buf->dirent_count = 1;
		return -EEXIST;
	}
	return 0;
}

/**
 * cifsd_vfs_lookup_in_dir() - lookup a file in a directory
 * @dirname:	directory name
 * @filename:	filename to lookup
 *
 * Return:	0 on success, otherwise error
 */
static int cifsd_vfs_lookup_in_dir(char *dirname, char *filename)
{
	struct path dir_path;
	int ret;
	struct file *dfilp;
	int flags = O_RDONLY|O_LARGEFILE;
	int dirnamelen = strlen(dirname);
	struct cifsd_readdir_data readdir_data = {
		.ctx.actor	= __caseless_lookup,
		.private	= filename,
		.used		= strlen(filename),
	};

	ret = cifsd_vfs_kern_path(dirname, 0, &dir_path, true);
	if (ret)
		goto error;

	dfilp = dentry_open(&dir_path, flags, current_cred());
	if (IS_ERR(dfilp)) {
		path_put(&dir_path);
		cifsd_err("cannot open directory %s\n", dirname);
		ret = -EINVAL;
		goto error;
	}

	ret = cifsd_vfs_readdir(dfilp, &readdir_data);
	if (readdir_data.dirent_count > 0)
		ret = 0;

	fput(dfilp);
	path_put(&dir_path);
error:
	dirname[dirnamelen] = '/';
	return ret;
}

/**
 * cifsd_vfs_kern_path() - lookup a file and get path info
 * @name:	name of file for lookup
 * @flags:	lookup flags
 * @path:	if lookup succeed, return path info
 * @caseless:	caseless filename lookup
 *
 * Return:	0 on success, otherwise error
 */
int cifsd_vfs_kern_path(char *name, unsigned int flags, struct path *path,
		bool caseless)
{
	char *filename = NULL;
	int err;

	err = kern_path(name, flags, path);
	if (!err)
		return err;

	if (caseless) {
		filename = extract_last_component(name);
		if (!filename)
			goto out;

		/* root reached */
		if (strlen(name) == 0)
			goto out;

		err = cifsd_vfs_lookup_in_dir(name, filename);
		if (err)
			goto out;
		err = kern_path(name, flags, path);
	}

out:
	roolback_path_modification(filename);
	return err;
}

/**
 * cifsd_vfs_init_kstat() - convert unix stat information to smb stat format
 * @p:          destination buffer
 * @cifsd_kstat:      cifsd kstat wrapper
 */
void *cifsd_vfs_init_kstat(char **p, struct cifsd_kstat *cifsd_kstat)
{
	FILE_DIRECTORY_INFO *info = (FILE_DIRECTORY_INFO *)(*p);
	u64 time;

	info->FileIndex = 0;
	info->CreationTime = cpu_to_le64(cifsd_kstat->create_time);
	time = cifs_UnixTimeToNT(from_kern_timespec(cifsd_kstat->kstat->atime));
	info->LastAccessTime = cpu_to_le64(time);
	time = cifs_UnixTimeToNT(from_kern_timespec(cifsd_kstat->kstat->mtime));
	info->LastWriteTime = cpu_to_le64(time);
	time = cifs_UnixTimeToNT(from_kern_timespec(cifsd_kstat->kstat->ctime));
	info->ChangeTime = cpu_to_le64(time);

	if (cifsd_kstat->file_attributes & FILE_ATTRIBUTE_DIRECTORY_LE) {
		info->EndOfFile = 0;
		info->AllocationSize = 0;
	} else {
		info->EndOfFile = cpu_to_le64(cifsd_kstat->kstat->size);
		info->AllocationSize =
			cpu_to_le64(cifsd_kstat->kstat->blocks << 9);
	}
	info->ExtFileAttributes = cifsd_kstat->file_attributes;

	return info;
}

int cifsd_vfs_fill_dentry_attrs(struct cifsd_work *work,
				struct dentry *dentry,
				struct cifsd_kstat *cifsd_kstat)
{
	generic_fillattr(d_inode(dentry), cifsd_kstat->kstat);
	__file_dentry_ctime(work, dentry, cifsd_kstat);
	__fill_dentry_attributes(work, dentry, cifsd_kstat);
	return 0;
}

ssize_t cifsd_vfs_casexattr_len(struct dentry *dentry,
				char *attr_name,
				int attr_name_len)
{
	char *name, *xattr_list = NULL;
	ssize_t value_len = -ENOENT, xattr_list_len;

	xattr_list_len = cifsd_vfs_listxattr(dentry, &xattr_list);
	if (xattr_list_len <= 0)
		goto out;

	for (name = xattr_list; name - xattr_list < xattr_list_len;
			name += strlen(name) + 1) {
		cifsd_debug("%s, len %zd\n", name, strlen(name));
		if (strncasecmp(attr_name, name, attr_name_len))
			continue;

		value_len = cifsd_vfs_xattr_len(dentry, name);
		break;
	}

out:
	cifsd_vfs_xattr_free(xattr_list);
	return value_len;
}

int cifsd_vfs_xattr_stream_name(char *stream_name,
				char **xattr_stream_name)
{
	int stream_name_size;
	int xattr_stream_name_size;
	char *xattr_stream_name_buf;

	stream_name_size = strlen(stream_name);
	xattr_stream_name_size = stream_name_size + XATTR_NAME_STREAM_LEN + 1;
	xattr_stream_name_buf = kmalloc(xattr_stream_name_size, GFP_KERNEL);

	memcpy(xattr_stream_name_buf,
		XATTR_NAME_STREAM,
		XATTR_NAME_STREAM_LEN);

	if (stream_name_size)
		memcpy(&xattr_stream_name_buf[XATTR_NAME_STREAM_LEN],
			stream_name,
			stream_name_size);

	xattr_stream_name_buf[xattr_stream_name_size - 1] = '\0';
	*xattr_stream_name = xattr_stream_name_buf;

	return xattr_stream_name_size;
}


static int cifsd_vfs_copy_file_range(struct file *file_in, loff_t pos_in,
				struct file *file_out, loff_t pos_out,
				size_t len)
{
	struct inode *inode_in = file_inode(file_in);
	struct inode *inode_out = file_inode(file_out);
	int ret;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0)
	ret = vfs_copy_file_range(file_in, pos_in, file_out, pos_out, len, 0);
	/* do splice for the copy between different file systems */
	if (ret != -EXDEV)
		return ret;
#endif

	if (S_ISDIR(inode_in->i_mode) || S_ISDIR(inode_out->i_mode))
		return -EISDIR;
	if (!S_ISREG(inode_in->i_mode) || !S_ISREG(inode_out->i_mode))
		return -EINVAL;

	if (!(file_in->f_mode & FMODE_READ) ||
	    !(file_out->f_mode & FMODE_WRITE))
		return -EBADF;

	if (len == 0)
		return 0;

	file_start_write(file_out);

	/*
	 * skip the verification of the range of data. it will be done
	 * in do_splice_direct
	 */
	ret = do_splice_direct(file_in, &pos_in, file_out, &pos_out,
			len > MAX_RW_COUNT ? MAX_RW_COUNT : len, 0);
	if (ret > 0) {
		fsnotify_access(file_in);
		add_rchar(current, ret);
		fsnotify_modify(file_out);
		add_wchar(current, ret);
	}

	inc_syscr(current);
	inc_syscw(current);

	file_end_write(file_out);
	return ret;
}

int cifsd_vfs_copy_file_ranges(struct cifsd_work *work,
				struct cifsd_file *src_fp,
				struct cifsd_file *dst_fp,
				struct srv_copychunk *chunks,
				unsigned int chunk_count,
				unsigned int *chunk_count_written,
				unsigned int *chunk_size_written,
				loff_t *total_size_written)
{
	unsigned int i;
	loff_t src_off, dst_off, src_file_size;
	size_t len;
	int ret;

	*chunk_count_written = 0;
	*chunk_size_written = 0;
	*total_size_written = 0;

	if (!(src_fp->daccess & (FILE_READ_DATA_LE | FILE_GENERIC_READ_LE |
			FILE_GENERIC_ALL_LE | FILE_MAXIMAL_ACCESS_LE |
			FILE_EXECUTE_LE))) {
		cifsd_err("no right to read(%s)\n", FP_FILENAME(src_fp));
		return -EACCES;
	}
	if (!(dst_fp->daccess & (FILE_WRITE_DATA_LE | FILE_APPEND_DATA_LE |
			FILE_GENERIC_WRITE_LE | FILE_GENERIC_ALL_LE |
			FILE_MAXIMAL_ACCESS_LE))) {
		cifsd_err("no right to write(%s)\n", FP_FILENAME(dst_fp));
		return -EACCES;
	}

	if (cifsd_stream_fd(src_fp) || cifsd_stream_fd(dst_fp))
		return -EBADF;

	smb_break_all_levII_oplock(work, dst_fp, 1);

	for (i = 0; i < chunk_count; i++) {
		src_off = le64_to_cpu(chunks[i].SourceOffset);
		dst_off = le64_to_cpu(chunks[i].TargetOffset);
		len = le32_to_cpu(chunks[i].Length);

		if (check_lock_range(src_fp->filp, src_off,
				src_off + len - 1, READ))
			return -EAGAIN;
		if (check_lock_range(dst_fp->filp, dst_off,
				dst_off + len - 1, WRITE))
			return -EAGAIN;
	}

	src_file_size = i_size_read(file_inode(src_fp->filp));

	for (i = 0; i < chunk_count; i++) {
		src_off = le64_to_cpu(chunks[i].SourceOffset);
		dst_off = le64_to_cpu(chunks[i].TargetOffset);
		len = le32_to_cpu(chunks[i].Length);

		if (src_off + len > src_file_size)
			return -E2BIG;

		ret = cifsd_vfs_copy_file_range(src_fp->filp, src_off,
				dst_fp->filp, dst_off, len);
		if (ret < 0)
			return ret;

		*chunk_count_written += 1;
		*total_size_written += ret;
	}
	return 0;
}

int cifsd_vfs_posix_lock_wait(struct file_lock *flock)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
	return wait_event_interruptible(flock->fl_wait, !flock->fl_next);
#else
	return wait_event_interruptible(flock->fl_wait, !flock->fl_blocker);
#endif
}

int cifsd_vfs_posix_lock_wait_timeout(struct file_lock *flock, long timeout)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
	return wait_event_interruptible_timeout(flock->fl_wait,
						!flock->fl_next,
						timeout);
#else
	return wait_event_interruptible_timeout(flock->fl_wait,
						!flock->fl_blocker,
						timeout);
#endif
}

void cifsd_vfs_posix_lock_unblock(struct file_lock *flock)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
	posix_unblock_lock(flock);
#else
	locks_delete_block(flock);
#endif
}
