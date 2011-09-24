/*
 * Copyright (C) 2011 Coriolis Technologies Pvt Ltd
 * Licensed under GPLv2
 */

#include <linux/stddef.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/ioport.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/blkdev.h>
#include <linux/list.h>
#include <linux/statfs.h>
#include <linux/stat.h>
#include <linux/kdev_t.h>
#include <asm/uaccess.h>
#include <asm/io.h>
#include "jlfs.h"

/* Request and result buffers, 1 page each */
static unsigned long requestbuf = 0;
static unsigned long resultbuf = 0;

DECLARE_MUTEX(jl_sem);
DECLARE_WAIT_QUEUE_HEAD(jl_wq);

static int intr_state = 0;
static int cmd_status = 0;

static int io_port = JLFS_IO_BASE;
static int irq = JLFS_IRQ;

module_param(io_port, int, 0);
MODULE_PARM_DESC(io_port, "IO port");

module_param(irq, int, 0);
MODULE_PARM_DESC(irq, "IRQ number");

int read_file(char *name, int fd, unsigned long long *offset, void *page, int len)
{
	int n, found;
    int ret = -EIO;
    unsigned long long addr;

    //addr = page_to_phys(page);
    addr = virt_to_phys(page);

    if (down_interruptible(&jl_sem)) {
        return -ERESTARTSYS;
    }
    intr_state = 0;
    snprintf((char *)requestbuf, PAGE_SIZE, "{\"file\":\"%s\", \"fd\":%d, \"addr\":%lld, \"offset\":%lld, \"len\":%d}", name, fd, addr, *offset, len);
    outl(JLFS_CMD_READ, JLFS_IO_WRITE_CMD);
    wait_event_interruptible(jl_wq, (intr_state == 1));
    if (cmd_status != JLFS_STATUS_OK) {
        printk(KERN_INFO "jlfs: read: status %d", cmd_status);
        ret = -cmd_status;
        goto out;
    }

    found = sscanf((char *)resultbuf, " { \"read\" : %d } ", &n);
    if (found != 1) {
        printk(KERN_INFO "jlfs: read: didn't get expected results");
        goto out;
    }
    *offset += n;
    ret = n;

out:
    up(&jl_sem);
    return ret;
}

int read_dir(void *stream, char *name, unsigned long long *pos,
	       unsigned long long *ino_out, int *len_out)
{
    unsigned long long ino;
    int ret = -EFAULT;
    int found;
    int i;

    if (down_interruptible(&jl_sem)) {
        return -ERESTARTSYS;
    }
    intr_state = 0;
    snprintf((char *)requestbuf, PAGE_SIZE, "{\"dir\": \"%s\", \"pos\": %lld}",
        (char *)stream, *pos);
    outl(JLFS_CMD_READDIR, JLFS_IO_WRITE_CMD);
    wait_event_interruptible(jl_wq, (intr_state == 1));
    if (cmd_status != JLFS_STATUS_OK) {
        printk(KERN_INFO "jlfs: readdir: status %d", cmd_status);
        ret = -cmd_status;
        goto out;
    }

    found = sscanf((char *)resultbuf, " { \"inode\" : %lld , \"name\" : \"%255s\" } ", &ino, name);
    for (i = 0; i < JLFS_MAXPATHLEN && name[i]; i++) {
        if (name[i] == '/') {
            name[i] = ' ';
        } else if (name[i] == '"') {
            name[i] = 0;
            break;
        }
    }
    //printk(KERN_INFO "jlfs: readdir cmd result: %s found %d inode %lld name #%s#", (char *)resultbuf, found, ino, name);
    if (found != 2) {
        printk(KERN_INFO "jlfs: readdir: didn't get expected results");
        goto out;
    }
    if (ino == 0) {
        ret = -ENOENT;
        goto out;
    }
    ret = 0;
    *ino_out = ino;
    (*pos)++;
    *len_out = strlen(name);
out:
    up(&jl_sem);
    return ret;
}

int stat_file(const char *path, unsigned long long *inode_out, int *mode_out,
	      int *nlink_out, int *uid_out, int *gid_out,
	      unsigned long long *size_out, struct timespec *atime_out,
	      struct timespec *mtime_out, struct timespec *ctime_out,
	      int *blksize_out, unsigned long long *blocks_out)
{
    unsigned long long ino;
    long long size;
    int mtime_sec, mtime_nsec, found;
    int err = -ENOENT;

    //printk(KERN_INFO "jlfs: stat_file %s", path);

    if (strcmp(path, "/") == 0) {
        JLFS_STAT_SET(inode_out, JLFS_ROOTINO); 
        JLFS_STAT_SET(mode_out, S_IFDIR | 0755);
        JLFS_STAT_SET(nlink_out, 2);
        JLFS_STAT_SET(uid_out, 0);
        JLFS_STAT_SET(gid_out, 0);
        JLFS_STAT_SET(size_out, 1024);
        if (atime_out) {
            atime_out->tv_sec = 0;
            atime_out->tv_nsec = 0;
        }
        if (mtime_out) {
            mtime_out->tv_sec = 0;
            mtime_out->tv_nsec = 0;
        }
        if (ctime_out) {
            ctime_out->tv_sec = 0;
            ctime_out->tv_nsec = 0;
        }
        JLFS_STAT_SET(blksize_out, JLFS_BLKSIZE);
        JLFS_STAT_SET(blocks_out, 1);
        return 0;
    }
            
    if (down_interruptible(&jl_sem)) {
        return -ERESTARTSYS;
    }
    intr_state = 0;
    snprintf((char *)requestbuf, PAGE_SIZE, "{\"file\": \"%s\"}", path);
    outl(JLFS_CMD_STAT, JLFS_IO_WRITE_CMD);
    wait_event_interruptible(jl_wq, (intr_state == 1));
    if (cmd_status != JLFS_STATUS_OK) {
        printk(KERN_INFO "jlfs: stat: status %d", cmd_status);
        err = -cmd_status;
        goto out;
    }

    found = sscanf((char *)resultbuf, " { \"inode\" : %lld , \"size\" : %lld , \"mtime_sec\" : %d , \"mtime_nsec\" : %d } ", &ino, &size, &mtime_sec, &mtime_nsec);
    if (found != 4) {
        printk(KERN_INFO "jlfs: stat: didn't get expected results");
        goto out;
    }
    JLFS_STAT_SET(inode_out, ino); 
    JLFS_STAT_SET(mode_out, S_IFREG | 0644);
    JLFS_STAT_SET(nlink_out, 1);
    JLFS_STAT_SET(uid_out, 0);
    JLFS_STAT_SET(gid_out, 0);
    JLFS_STAT_SET(size_out, size);
    if (atime_out) {
        atime_out->tv_sec = mtime_sec;
        atime_out->tv_nsec = mtime_nsec;
    }
    if (mtime_out) {
        mtime_out->tv_sec = mtime_sec;
        mtime_out->tv_nsec = mtime_nsec;
    }
    if (ctime_out) {
        ctime_out->tv_sec = mtime_sec;
        ctime_out->tv_nsec = mtime_nsec;
    }
    JLFS_STAT_SET(blksize_out, JLFS_BLKSIZE);
    JLFS_STAT_SET(blocks_out, size / JLFS_BLKSIZE);
    err = 0;
out:
    up(&jl_sem);
	return err;
}

int access_file(char *path, int r, int w, int x)
{
    return 0;
}

int open_file(char *path, int r, int w, int append)
{
    unsigned long long ino;
    long long size;
    int mtime_sec, mtime_nsec, found;
    int ret = -ENOENT;
            
    //printk(KERN_INFO "jlfs: open_file %s", path);

    if (down_interruptible(&jl_sem)) {
        return -ERESTARTSYS;
    }
    intr_state = 0;
    snprintf((char *)requestbuf, PAGE_SIZE, "{\"file\": \"%s\"}", path);
    outl(JLFS_CMD_STAT, JLFS_IO_WRITE_CMD);
    wait_event_interruptible(jl_wq, (intr_state == 1));
    if (cmd_status != JLFS_STATUS_OK) {
        printk(KERN_INFO "jlfs: stat: status %d", cmd_status);
        goto out;
    }

    found = sscanf((char *)resultbuf, " { \"inode\" : %lld , \"size\" : %lld , \"mtime_sec\" : %d , \"mtime_nsec\" : %d } ", &ino, &size, &mtime_sec, &mtime_nsec);
    if (found != 4) {
        printk(KERN_INFO "jlfs: stat: didn't get expected results");
        goto out;
    }
    //printk(KERN_INFO "jlfs: open_file got ino %d", (int)ino);
    ret = (int)ino;
    
out:
    up(&jl_sem);
    return ret;
}

void *open_dir(char *path, int *err_out)
{
    //printk(KERN_INFO "jlfs: open_dir %s", path);
    if (strcmp(path, "/")) {
        *err_out = ENOENT;
        return NULL;
    } else {
        return "/";
    }
}

int lseek_file(int fd, long long offset, int whence)
{
#if 0
	int ret;

	ret = lseek64(fd, offset, whence);
	if(ret < 0)
		return(-errno);
#endif
	return(0);
}

int test_cmd(void)
{
    if (down_interruptible(&jl_sem)) {
        return -ERESTARTSYS;
    }
    intr_state = 0;
    sprintf((char *)requestbuf, "JLFS Test Command");
    cmd_status = inl(JLFS_IO_READ_STATUS);
    outl(JLFS_CMD_TEST, JLFS_IO_WRITE_CMD);
    wait_event_interruptible(jl_wq, (intr_state == 1));
    printk(KERN_INFO "jlfs: test cmd result: %s", (char *)resultbuf);
    up(&jl_sem);
    return 1;
}

irqreturn_t jlfs_interrupt(int irq, void *dev_id)
{
    intr_state = 1;
    cmd_status = inl(JLFS_IO_READ_STATUS);
    outl(JLFS_CMD_IRQACK, JLFS_IO_WRITE_CMD);
    wake_up_interruptible(&jl_wq);
    return 1;
}

int init_jlfs_backend(void)
{
    printk(KERN_DEBUG "init_jlfs_backend");
    if (!request_region(JLFS_IO_BASE, 16, "jlfs")) {
        printk(KERN_INFO "jlfs: request region failed");
        return -1;
    }
    if (request_irq(irq, jlfs_interrupt, 0, "jlfs", &intr_state)) {
        printk(KERN_INFO "jlfs: request_irq failed");
        return -1;
    }
    if (inl(JLFS_IO_BASE) != JLFS_SUPER_MAGIC) {
        printk(KERN_INFO "No coffee, no workee");
        return -1;
    }
    outl(0xdeadbeef, JLFS_IO_BASE);

    requestbuf = __get_free_page(GFP_KERNEL);
    resultbuf = __get_free_page(GFP_KERNEL);
    if (!requestbuf || !resultbuf) {
        printk(KERN_INFO "jlfs: Could not allocate buffers");
        return -1;
    }
    //printk("jlfs: requestbuf: %p resultbuf %p", virt_to_phys((void *)requestbuf),
     //   virt_to_phys((void *)resultbuf));
    outl(virt_to_phys((void *)requestbuf), JLFS_IO_WRITE_REQUESTBUF);
    outl(virt_to_phys((void *)resultbuf), JLFS_IO_WRITE_RESULTBUF);

    test_cmd();
    return 0;
}

void deinit_jlfs_backend(void)
{
    if (requestbuf) {
        free_page(requestbuf);
        requestbuf = 0;
    }
    if (resultbuf) {
        free_page(resultbuf);
        resultbuf = 0;
    }
    outl(JLFS_IO_BASE, 0x600db1e);

    return;
}

int do_statfs(char *root, long *bsize_out, long long *blocks_out,
	      long long *bfree_out, long long *bavail_out,
	      long long *files_out, long long *ffree_out,
	      void *fsid_out, int fsid_size, long *namelen_out,
	      long *spare_out)
{
#if 0
	struct statfs64 buf;
	int err;

	err = statfs64(root, &buf);
	if(err < 0) return(-errno);
	*bsize_out = buf.f_bsize;
	*blocks_out = buf.f_blocks;
	*bfree_out = buf.f_bfree;
	*bavail_out = buf.f_bavail;
	*files_out = buf.f_files;
	*ffree_out = buf.f_ffree;
	memcpy(fsid_out, &buf.f_fsid,
	       sizeof(buf.f_fsid) > fsid_size ? fsid_size :
	       sizeof(buf.f_fsid));
	*namelen_out = buf.f_namelen;
	spare_out[0] = buf.f_spare[0];
	spare_out[1] = buf.f_spare[1];
	spare_out[2] = buf.f_spare[2];
	spare_out[3] = buf.f_spare[3];
	spare_out[4] = buf.f_spare[4];
#endif
	return(0);
}

void close_file(void *stream)
{
}

void close_dir(void *stream)
{
}
