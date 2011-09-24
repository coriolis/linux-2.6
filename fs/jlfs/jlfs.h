/*
 * Copyright (C) 2011 Coriolis Technologies Pvt Ltd
 * Licensed under GPLv2
 *
 * Derived from hostfs, which is Copyright (C) Jeff Dike (jdike@karaya.com)
 *
 */

#ifndef __FS_JLFS
#define __FS_JLFS

#include <linux/stddef.h>
#include <linux/interrupt.h>

/*
 * Backend definitions
 */

#define JLFS_IO_BASE 0x180
#define JLFS_IO_READ_STATUS (io_port + 4)
#define JLFS_IO_WRITE_CMD (io_port + 4)
#define JLFS_IO_WRITE_REQUESTBUF (io_port + 8)
#define JLFS_IO_WRITE_RESULTBUF (io_port + 12)

#define JLFS_IRQ 5
#define JLFS_SUPER_MAGIC 0xf1c0ffee


/* Commands */

#define JLFS_CMD_IRQACK 0x1
#define JLFS_CMD_TEST 0x2
#define JLFS_CMD_READ 0x3
#define JLFS_CMD_WRITE 0x4
#define JLFS_CMD_READDIR 0x5
#define JLFS_CMD_STAT 0x6

/* Status register values */

#define JLFS_STATUS_OK 0xa0a0
#define JLFS_STATUS_UNKNOWN_CMD 0xa0a1
#define JLFS_STATUS_NOK 0xa0a2

/* FS definitions */
#define JLFS_MAXPATHLEN 256
#define JLFS_ROOTINO 65535
#define JLFS_BLKSIZE 1024
#define JLFS_MAX_FILESIZE ((1ULL << 36) - 1)


#define JLFS_STAT_SET(attr, value) do {if (attr) { *(attr) = value; }} while (0)
/* These are exactly the same definitions as in fs.h, but the names are
 * changed so that this file can be included in both kernel and user files.
 */

#define JLFS_ATTR_MODE	1
#define JLFS_ATTR_UID 	2
#define JLFS_ATTR_GID 	4
#define JLFS_ATTR_SIZE	8
#define JLFS_ATTR_ATIME	16
#define JLFS_ATTR_MTIME	32
#define JLFS_ATTR_CTIME	64
#define JLFS_ATTR_ATIME_SET	128
#define JLFS_ATTR_MTIME_SET	256

/* These two are unused by jlfs. */
#define JLFS_ATTR_FORCE	512	/* Not a change, but a change it */
#define JLFS_ATTR_ATTR_FLAG	1024

extern int init_jlfs_backend(void);
extern void deinit_jlfs_backend(void);
extern irqreturn_t jlfs_interrupt(int irq, void *dev_id);
extern int stat_file(const char *path, unsigned long long *inode_out,
		     int *mode_out, int *nlink_out, int *uid_out, int *gid_out,
		     unsigned long long *size_out, struct timespec *atime_out,
		     struct timespec *mtime_out, struct timespec *ctime_out,
		     int *blksize_out, unsigned long long *blocks_out);
extern int access_file(char *path, int r, int w, int x);
extern int open_file(char *path, int r, int w, int append);
extern int file_type(const char *path, int *maj, int *min);
extern void *open_dir(char *path, int *err_out);
extern int read_dir(void *stream, char *name, unsigned long long *pos,
		      unsigned long long *ino_out, int *len_out);
extern void close_file(void *stream);
extern void close_dir(void *stream);
extern int read_file(char *name, int fd, unsigned long long *offset, void *page, int len);
extern int lseek_file(int fd, long long offset, int whence);
extern int do_statfs(char *root, long *bsize_out, long long *blocks_out,
		     long long *bfree_out, long long *bavail_out,
		     long long *files_out, long long *ffree_out,
		     void *fsid_out, int fsid_size, long *namelen_out,
		     long *spare_out);

#endif

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
