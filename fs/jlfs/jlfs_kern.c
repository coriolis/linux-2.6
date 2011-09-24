/*
 * Copyright (C) 2011 Coriolis Technologies Pvt Ltd
 *
 * Derived from hostfs, which is Copyright (C) Jeff Dike (jdike@karaya.com)
 *
 * Licensed under GPLv2
 */

#include <linux/stddef.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/blkdev.h>
#include <linux/list.h>
#include <linux/statfs.h>
#include <linux/kdev_t.h>
#include <asm/uaccess.h>
#include "jlfs.h"

struct jlfs_inode_info {
	char *host_filename;
	int fd;
	int mode;
	struct inode vfs_inode;
};

static inline struct jlfs_inode_info *JLFS_I(struct inode *inode)
{
	return(list_entry(inode, struct jlfs_inode_info, vfs_inode));
}

#define FILE_JLFS_I(file) JLFS_I((file)->f_path.dentry->d_inode)

int jlfs_d_delete(struct dentry *dentry)
{
	return(1);
}

struct dentry_operations jlfs_dentry_ops = {
	.d_delete		= jlfs_d_delete,
};

/* Changed in jlfs_args before the kernel starts running */
static char *root_ino = "/";
static int append = 0;


static struct inode_operations jlfs_iops;
static struct inode_operations jlfs_dir_iops;

static char *dentry_name(struct dentry *dentry, int extra)
{
	struct dentry *parent;
	char *root, *name;
	int len;

	len = 0;
	parent = dentry;
	while(parent->d_parent != parent){
		len += parent->d_name.len + 1;
		parent = parent->d_parent;
	}

	root = JLFS_I(parent->d_inode)->host_filename;
	len += strlen(root);
	name = kmalloc(len + extra + 1, GFP_KERNEL);
	if(name == NULL) return(NULL);

	name[len] = '\0';
	parent = dentry;
	while(parent->d_parent != parent){
		len -= parent->d_name.len + 1;
		name[len] = '/';
		strncpy(&name[len + 1], parent->d_name.name,
			parent->d_name.len);
		parent = parent->d_parent;
	}
	strncpy(name, root, strlen(root));
	return(name);
}

static char *inode_name(struct inode *ino, int extra)
{
	struct dentry *dentry;

	dentry = list_entry(ino->i_dentry.next, struct dentry, d_alias);
	return(dentry_name(dentry, extra));
}

static int read_name(struct inode *ino, char *name)
{
	/* The non-int inode fields are copied into ints by stat_file and
	 * then copied into the inode because passing the actual pointers
	 * in and having them treated as int * breaks on big-endian machines
	 */
	int err;
	int i_mode, i_nlink, i_blksize;
	unsigned long long i_size;
	unsigned long long i_ino;
	unsigned long long i_blocks;

	err = stat_file(name, &i_ino, &i_mode, &i_nlink, &ino->i_uid,
			&ino->i_gid, &i_size, &ino->i_atime, &ino->i_mtime,
			&ino->i_ctime, &i_blksize, &i_blocks);
	if(err)
		return(err);

	ino->i_ino = i_ino;
	ino->i_mode = i_mode;
	ino->i_nlink = i_nlink;
	ino->i_size = i_size;
	ino->i_blocks = i_blocks;
	return(0);
}

static int read_inode(struct inode *ino)
{
	char *name;
	int err = 0;

	/* Unfortunately, we are called from iget() when we don't have a dentry
	 * allocated yet.
	 */
	if(list_empty(&ino->i_dentry))
		goto out;

	err = -ENOMEM;
	name = inode_name(ino, 0);
	if(name == NULL)
		goto out;
	err = read_name(ino, name);
	kfree(name);
 out:
	return(err);
}

int jlfs_statfs(struct dentry *dentry, struct kstatfs *sf)
{
	/* do_statfs uses struct statfs64 internally, but the linux kernel
	 * struct statfs still has 32-bit versions for most of these fields,
	 * so we convert them here
	 */
	int err;
	long long f_blocks;
	long long f_bfree;
	long long f_bavail;
	long long f_files;
	long long f_ffree;

	err = do_statfs(JLFS_I(dentry->d_sb->s_root->d_inode)->host_filename,
			&sf->f_bsize, &f_blocks, &f_bfree, &f_bavail, &f_files,
			&f_ffree, &sf->f_fsid, sizeof(sf->f_fsid),
			&sf->f_namelen, sf->f_spare);
	if(err) return(err);
	sf->f_blocks = f_blocks;
	sf->f_bfree = f_bfree;
	sf->f_bavail = f_bavail;
	sf->f_files = f_files;
	sf->f_ffree = f_ffree;
	sf->f_type = JLFS_SUPER_MAGIC;
	return(0);
}

static struct inode *jlfs_alloc_inode(struct super_block *sb)
{
	struct jlfs_inode_info *hi;

	hi = kmalloc(sizeof(*hi), GFP_KERNEL);
	if(hi == NULL)
		return(NULL);

	*hi = ((struct jlfs_inode_info) { .host_filename	= NULL,
					    .fd			= -1,
					    .mode		= 0 });
	inode_init_once(&hi->vfs_inode);
	return(&hi->vfs_inode);
}

static void jlfs_delete_inode(struct inode *inode)
{
	truncate_inode_pages(&inode->i_data, 0);
	if(JLFS_I(inode)->fd != -1) {
		close_file(&JLFS_I(inode)->fd);
		JLFS_I(inode)->fd = -1;
	}
	clear_inode(inode);
}

static void jlfs_destroy_inode(struct inode *inode)
{
	kfree(JLFS_I(inode)->host_filename);

	/*XXX: This should not happen, probably. The check is here for
	 * additional safety.*/
	if(JLFS_I(inode)->fd != -1) {
		close_file(&JLFS_I(inode)->fd);
		printk(KERN_DEBUG "Closing host fd in .destroy_inode\n");
	}

	kfree(JLFS_I(inode));
}

static void jlfs_read_inode(struct inode *inode)
{
	read_inode(inode);
}

static struct super_operations jlfs_sbops = {
	.alloc_inode	= jlfs_alloc_inode,
	.drop_inode	= generic_delete_inode,
	.delete_inode   = jlfs_delete_inode,
	.destroy_inode	= jlfs_destroy_inode,
	.read_inode	= jlfs_read_inode,
	.statfs		= jlfs_statfs,
};

int jlfs_readdir(struct file *file, void *ent, filldir_t filldir)
{
	void *dir;
	char *name;
	unsigned long long next, ino;
	int error, len;

	name = dentry_name(file->f_path.dentry, 0);
	if(name == NULL) return(-ENOMEM);
	dir = open_dir(name, &error);
	kfree(name);
	if(dir == NULL) return(-error);
    name = kmalloc(JLFS_MAXPATHLEN, GFP_KERNEL);
	next = file->f_pos;
	while(read_dir(dir, name, &next, &ino, &len) == 0){
		error = (*filldir)(ent, name, len, file->f_pos,
				   ino, DT_UNKNOWN);
		if(error) break;
		file->f_pos = next;
	}
	close_dir(dir);
    kfree(name);
	return(0);
}

int jlfs_file_open(struct inode *ino, struct file *file)
{
	char *name;
	int mode = 0, r = 0, w = 0, fd;

	mode = file->f_mode & (FMODE_READ | FMODE_WRITE);
	if((mode & JLFS_I(ino)->mode) == mode)
		return(0);

	/* The file may already have been opened, but with the wrong access,
	 * so this resets things and reopens the file with the new access.
	 */
	if(JLFS_I(ino)->fd != -1){
		close_file(&JLFS_I(ino)->fd);
		JLFS_I(ino)->fd = -1;
	}

	JLFS_I(ino)->mode |= mode;
	if(JLFS_I(ino)->mode & FMODE_READ)
		r = 1;
	if(JLFS_I(ino)->mode & FMODE_WRITE)
		w = 1;
	if(w)
		r = 1;

	name = dentry_name(file->f_path.dentry, 0);
	if(name == NULL)
		return(-ENOMEM);
	fd = open_file(name, r, w, append);
	kfree(name);
	if(fd < 0) return(fd);
	FILE_JLFS_I(file)->fd = fd;

	return(0);
}

static const struct file_operations jlfs_file_fops = {
	.llseek		= generic_file_llseek,
	.read		= do_sync_read,
	.sendfile	= NULL,
	.aio_read	= generic_file_aio_read,
	.aio_write	= NULL,
	.write		= NULL,
	.mmap		= generic_file_mmap,
	.open		= jlfs_file_open,
	.release	= NULL,
	.fsync		= NULL,
};

static const struct file_operations jlfs_dir_fops = {
	.llseek		= generic_file_llseek,
	.readdir	= jlfs_readdir,
	.read		= generic_read_dir,
};

int jlfs_readpage(struct file *file, struct page *page)
{
	char *buffer;
	long long start;
	int err = 0;
    char *name;

	start = (long long) page->index << PAGE_CACHE_SHIFT;
	buffer = kmap(page);
	name = dentry_name(file->f_path.dentry, 0);
	if(name == NULL)
		return(-ENOMEM);
	err = read_file(name, FILE_JLFS_I(file)->fd, &start, buffer,
			PAGE_CACHE_SIZE);
	kfree(name);
	if(err < 0) goto out;

	memset(&buffer[err], 0, PAGE_CACHE_SIZE - err);
    //printk (KERN_INFO "jlfs_readpage: got bytes %d %d %d %d", buffer[0], buffer[1], buffer[2], buffer[3]);

	flush_dcache_page(page);
	SetPageUptodate(page);
	if (PageError(page)) ClearPageError(page);
	err = 0;
 out:
	kunmap(page);
	unlock_page(page);
	return(err);
}

static const struct address_space_operations jlfs_aops = {
	.writepage 	= NULL,
	.readpage	= jlfs_readpage,
	.set_page_dirty = NULL,
	.prepare_write	= NULL,
	.commit_write	= NULL
};

static int init_inode(struct inode *inode, struct dentry *dentry)
{
	char *name;
	int type = 0, err = -ENOMEM;

	if (dentry) {
		name = dentry_name(dentry, 0);
		if(name == NULL) {
			goto out;
        }
        if (strcmp(name, "/") == 0) {
            type = 1;
        }
		kfree(name);
	} else {
        type = 1;
    }

    if (type == 1) { /* Directory */
        inode->i_op = &jlfs_dir_iops;
        inode->i_fop = &jlfs_dir_fops;
    } else { /* Regular file */
        inode->i_op = &jlfs_iops;
        inode->i_fop = &jlfs_file_fops;
    }
    inode->i_mapping->a_ops = &jlfs_aops;
    err = 0;

 out:
	return err;
}

struct dentry *jlfs_lookup(struct inode *ino, struct dentry *dentry,
                            struct nameidata *nd)
{
	struct inode *inode;
	char *name;
	int err;

	err = -ENOMEM;
	inode = iget(ino->i_sb, 0);
	if(inode == NULL)
		goto out;

	err = init_inode(inode, dentry);
	if(err)
		goto out_put;

	err = -ENOMEM;
	name = dentry_name(dentry, 0);
	if(name == NULL)
		goto out_put;
	err = read_name(inode, name);
	kfree(name);
	if(err == -ENOENT){
		iput(inode);
		inode = NULL;
	}
	else if(err)
		goto out_put;

	d_add(dentry, inode);
	dentry->d_op = &jlfs_dentry_ops;
	return(NULL);

 out_put:
	iput(inode);
 out:
	return(ERR_PTR(err));
}

int jlfs_permission(struct inode *ino, int desired, struct nameidata *nd)
{
	char *name;
	int r = 0, w = 0, x = 0, err;

	if (desired & MAY_READ) r = 1;
	if (desired & MAY_WRITE) w = 1;
	if (desired & MAY_EXEC) x = 1;
	name = inode_name(ino, 0);
	if (name == NULL) return(-ENOMEM);

	if (S_ISCHR(ino->i_mode) || S_ISBLK(ino->i_mode) ||
			S_ISFIFO(ino->i_mode) || S_ISSOCK(ino->i_mode))
		err = 0;
	else
		err = access_file(name, r, w, x);
	kfree(name);
	if(!err)
		err = generic_permission(ino, desired, NULL);
	return err;
}

int jlfs_getattr(struct vfsmount *mnt, struct dentry *dentry,
	   struct kstat *stat)
{
	generic_fillattr(dentry->d_inode, stat);
	return(0);
}

static struct inode_operations jlfs_iops = {
	.create		= NULL,
	.link		= NULL,
	.unlink		= NULL,
	.symlink	= NULL,
	.mkdir		= NULL,
	.rmdir		= NULL,
	.mknod		= NULL,
	.rename		= NULL,
	.permission	= jlfs_permission,
	.setattr	= NULL,
	.getattr	= jlfs_getattr,
};

static struct inode_operations jlfs_dir_iops = {
	.create		= NULL,
	.lookup		= jlfs_lookup,
	.link		= NULL,
	.unlink		= NULL,
	.symlink	= NULL,
	.mkdir		= NULL,
	.rmdir		= NULL,
	.mknod		= NULL,
	.rename		= NULL,
	.permission	= jlfs_permission,
	.setattr	= NULL,
	.getattr	= jlfs_getattr,
};

static int jlfs_fill_sb_common(struct super_block *sb, void *d, int silent)
{
	struct inode *root_inode;
	char *name, *data = d;
	int err;


	sb->s_blocksize = 1024;
	sb->s_blocksize_bits = 10;
    sb->s_maxbytes = JLFS_MAX_FILESIZE;
	sb->s_magic = JLFS_SUPER_MAGIC;
	sb->s_op = &jlfs_sbops;

	if((data == NULL) || (*data == '\0'))
		data = root_ino;

	err = -ENOMEM;
	name = kmalloc(strlen(data) + 1, GFP_KERNEL);
	if(name == NULL)
		goto out;

	strcpy(name, data);

	root_inode = iget(sb, 0);
	if(root_inode == NULL)
		goto out_free;

	err = init_inode(root_inode, NULL);
	if(err)
		goto out_put;

	JLFS_I(root_inode)->host_filename = name;

	err = -ENOMEM;
	sb->s_root = d_alloc_root(root_inode);
	if(sb->s_root == NULL)
		goto out_put;

	err = read_inode(root_inode);
	if(err){
                /* No iput in this case because the dput does that for us */
                dput(sb->s_root);
                sb->s_root = NULL;
		goto out_free;
        }

	return(0);

 out_put:
        iput(root_inode);
 out_free:
	kfree(name);
 out:
	return(err);
}

static int jlfs_read_sb(struct file_system_type *type,
			  int flags, const char *dev_name,
			  void *data, struct vfsmount *mnt)
{
    printk(KERN_INFO "jlfs_read_sb");
	return get_sb_nodev(type, flags, data, jlfs_fill_sb_common, mnt);
}

static struct file_system_type jlfs_type = {
	.owner 		= THIS_MODULE,
	.name 		= "jlfs",
	.get_sb 	= jlfs_read_sb,
	.kill_sb	= kill_anon_super,
	.fs_flags 	= 0,
};

static int __init init_jlfs(void)
{
    if (init_jlfs_backend()) {
        return -1;
    }
	return register_filesystem(&jlfs_type);
}

static void __exit exit_jlfs(void)
{
    deinit_jlfs_backend();
	unregister_filesystem(&jlfs_type);
}

module_init(init_jlfs)
module_exit(exit_jlfs)
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Coriolis Technologies Pvt Ltd");

/*
 * Overrides for Emacs so that we follow Linus's tabbing style.
 * Emacs will notice this stuff at the end of the file and automatically
 * adjust the settings for this buffer only.  This must remain at the end
 * of the file.
 * ---------------------------------------------------------------------------
 * Local variables:
 * c-file-style: "linux"
 * End:
 */
