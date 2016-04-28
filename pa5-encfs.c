/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  Minor modifications and note by Andy Sayler (2012) <www.andysayler.com>
  Encrypt FS implementation by Jake Traut

  Source: fuse-2.8.7.tar.gz examples directory
  http://sourceforge.net/projects/fuse/files/fuse-2.X/

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

 gcc -c -g -Wall -Wextra `pkg-config fuse --cflags` pa5-encfs.c
 gcc -g -Wall -Wextra pa5-encfs.o aes-crypt.o -o pa5-encfs `pkg-config fuse --libs` -lcrypto	

  References:
	http://www.cs.nmsu.edu/~pfeiffer/fuse-tutorial/html/index.html
	http://gauss.ececs.uc.edu/Courses/c4029/code/fuse/notes.html
	http://stackoverflow.com/questions/19564797/difference-between-fclose-and-close
	https://www.ibm.com/support/knowledgecenter/ssw_ibm_i_72/rtref/fseek.htm
*/

#define FUSE_USE_VERSION 28
#define HAVE_SETXATTR

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include "aes-crypt.h"
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

struct vfs_state 
{
	//cast private data field here
	char *key; //<Key Phrase>
	char *mirrordir; //<Mirror Directory>
	char *mountpt; //<Mount Point>
};

#define VFS_DATA ((struct vfs_state *) fuse_get_context()->private_data)
#define FLAG_NAME "user.pa5-encfs.encrypted"

static void mirdir(char mpath[PATH_MAX], const char *path)
{
	strcpy(mpath, VFS_DATA->mirrordir);
	strncat(mpath, path, PATH_MAX);
}

int crypt_status(const char *path)
{
	int res = 0; //return 1 if encryption xattr is set
	char value[5]; //can be true or false
	getxattr(path, FLAG_NAME, value, sizeof("false"));
	if(strcmp(value, "true")) res = 1;
	
	return res;
}

static int xmp_getattr(const char *path, struct stat *stbuf)
{
	int res;
	char mpath[PATH_MAX];
	mirdir(mpath, path);
	
	res = lstat(mpath, stbuf);
	if (res == -1)
		return -errno;

	return res;
}

static int xmp_access(const char *path, int mask)
{
	int res;
	char mpath[PATH_MAX];
	mirdir(mpath, path);
	
	res = access(mpath, mask);
	if (res == -1)
		return -errno;

	return res;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
	int res;
	char mpath[PATH_MAX];
	mirdir(mpath, path);
	
	res = readlink(mpath, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return res;
}


static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	DIR *dp;
	struct dirent *de;
	char mpath[PATH_MAX];
	mirdir(mpath, path);	

	(void) offset;
	(void) fi;

	dp = opendir(mpath);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0))
			break;
	}

	closedir(dp);
	return 0;
}

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;
	char mpath[PATH_MAX];
	mirdir(mpath, path);

	/* On Linux this could just be 'mknod(path, mode, rdev)' but this
	   is more portable */
	if (S_ISREG(mode)) {
		res = open(mpath, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(mpath, mode);
	else
		res = mknod(mpath, mode, rdev);
	if (res == -1)
		return -errno;

	return res;
}

static int xmp_mkdir(const char *path, mode_t mode)
{
	int res;
	char mpath[PATH_MAX];
	mirdir(mpath, path);
	
	res = mkdir(mpath, mode);
	if (res == -1)
		return -errno;

	return res;
}

static int xmp_unlink(const char *path)
{
	int res;
	char mpath[PATH_MAX];
	mirdir(mpath, path);
	
	res = unlink(mpath);
	if (res == -1)
		return -errno;

	return res;
}

static int xmp_rmdir(const char *path)
{
	int res;
	char mpath[PATH_MAX];
	mirdir(mpath, path);
	
	res = rmdir(mpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_symlink(const char *from, const char *to)
{
	int res;

	res = symlink(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rename(const char *from, const char *to)
{
	int res;

	res = rename(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_link(const char *from, const char *to)
{
	int res;

	res = link(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chmod(const char *path, mode_t mode)
{
	int res;
	char mpath[PATH_MAX];
	mirdir(mpath, path);
	
	res = chmod(mpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;
	char mpath[PATH_MAX];
	mirdir(mpath, path);

	res = lchown(mpath, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_truncate(const char *path, off_t size)
{
	int res;
	char mpath[PATH_MAX];
	mirdir(mpath, path);

	res = truncate(mpath, size);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_utimens(const char *path, const struct timespec ts[2])
{
	int res;
	struct timeval tv[2];

	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

	char mpath[PATH_MAX];
	mirdir(mpath, path);

	res = utimes(mpath, tv);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
	int res;
	char mpath[PATH_MAX];
	mirdir(mpath, path);

	res = open(mpath, fi->flags);
	if (res == -1)
		return -errno;

	close(res);
	return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	//use fopen()/fclose() for file streams with FILE *ptr
	//use open()/close() for file descriptors with int fd
	FILE *inptr, *outptr;
	int res, action;
	char mpath[PATH_MAX];
	mirdir(mpath, path);

	(void) fi;
	inptr = fopen(mpath, "r");
	outptr = tmpfile();
	
	if(inptr == NULL || outptr == NULL) return -errno;
	
	if(crypt_status(mpath)) action = 0; //if currently encrypted, then decrypt and read
	else action = -1; //else just pass-through
	
	/* int do_crypt(FILE* in, FILE* out, int action, char* key_str)
	 * Purpose: Perform cipher on in File* and place result in out File*
	 * Args: FILE* in      : Input File Pointer
	 *       FILE* out     : Output File Pointer
	 *       int action    : Cipher action (1=encrypt, 0=decrypt, -1=pass-through (copy))
	 *	 char* key_str : C-string containing passpharse from which key is derived
	 * Return: FAILURE on error, SUCCESS on success
	 */	
	if(!do_crypt(inptr, outptr, action, VFS_DATA->key)) return -errno;
	
	//change file position to the offset, starting from beginning of file (SEEK_SET)
	fseeko(outptr, offset, SEEK_SET); //same as fseek but take offset of type off_t
	
	//now ready to read to the buffer
	res = fread(buf, sizeof(char), size, outptr);
	if(res == -1) return -errno;
	fclose(inptr);
	fclose(outptr);
	
	return res;
}

static int xmp_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	FILE *inptr, *outptr;
	int res, action;
	char mpath[PATH_MAX];
	mirdir(mpath, path);

	(void) fi;
	inptr = fopen(mpath, "rw+");
	outptr = tmpfile();
	
	if(inptr == NULL || outptr == NULL) return -errno;
	
	//check if need to encrypt before writing to mirror
	if(crypt_status(mpath)) action = 1; //if encrypted file, then data writing also should be encrypted
	else action = -1; //or pass through
	
	//first write all previous data to the out file
	if(!do_crypt(inptr, outptr, 0, VFS_DATA->key)) return -errno;
	//be more careful here, shouldnt decrypt file thats not encrypted 
	
	//change file position to offset, then write from buffer to stream
	fseeko(outptr, offset, SEEK_SET);
	res = fwrite(buf, sizeof(char), size, outptr);
	if(res == -1) return -errno;
	
	//now copy all data in outstream back (old + new)
	fseek(outptr, 0, SEEK_SET);
	if(!do_crypt(outptr, inptr, action, VFS_DATA->key)) return -errno;
	
	fclose(inptr);
	fclose(outptr);
	
	return res;
}

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
	int res;
	char mpath[PATH_MAX];
	mirdir(mpath, path);
	
	res = statvfs(mpath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_create(const char* path, mode_t mode, struct fuse_file_info* fi)
{
    (void) fi;
	char mpath[PATH_MAX];
	mirdir(mpath, path);
	
	printf("mpath is %s\n",mpath);
	printf("mountpt is %s\n",VFS_DATA->mountpt);
    int res;
    res = creat(mpath, mode);
    if(res == -1)
		return -errno;

    close(res);
    
	//extended attribute name:value pairs for encryption
	res = setxattr(mpath, FLAG_NAME, "true", sizeof("true"), 0);  
	
	if(res == -1) return -errno;

    return res;
}


static int xmp_release(const char *path, struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) fi;
	return 0;
}

static int xmp_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) isdatasync;
	(void) fi;
	return 0;
}

#ifdef HAVE_SETXATTR
static int xmp_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
	char mpath[PATH_MAX];
	mirdir(mpath, path);
		
	int res = lsetxattr(mpath, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	char mpath[PATH_MAX];
	mirdir(mpath, path);
		
	int res = lgetxattr(mpath, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_listxattr(const char *path, char *list, size_t size)
{
	char mpath[PATH_MAX];
	mirdir(mpath, path);
		
	int res = llistxattr(mpath, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_removexattr(const char *path, const char *name)
{
	char mpath[PATH_MAX];
	mirdir(mpath, path);
		
	int res = lremovexattr(mpath, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */

static struct fuse_operations xmp_oper = {
	.getattr	= xmp_getattr,
	.access		= xmp_access,
	.readlink	= xmp_readlink,
	.readdir	= xmp_readdir,
	.mknod		= xmp_mknod,
	.mkdir		= xmp_mkdir,
	.symlink	= xmp_symlink,
	.unlink		= xmp_unlink,
	.rmdir		= xmp_rmdir,
	.rename		= xmp_rename,
	.link		= xmp_link,
	.chmod		= xmp_chmod,
	.chown		= xmp_chown,
	.truncate	= xmp_truncate,
	.utimens	= xmp_utimens,
	.open		= xmp_open,
	.read		= xmp_read,
	.write		= xmp_write,
	.statfs		= xmp_statfs,
	.create         = xmp_create,
	.release	= xmp_release,
	.fsync		= xmp_fsync,
#ifdef HAVE_SETXATTR
	.setxattr	= xmp_setxattr,
	.getxattr	= xmp_getxattr,
	.listxattr	= xmp_listxattr,
	.removexattr	= xmp_removexattr,
#endif
};

int main(int argc, char *argv[])
{
	umask(0);
	struct vfs_state *vfs_data;
	
	if(argc < 4){
		printf("Not enough arguments. Run ./pa5-encfs <Key Phrase> <Mirror Directory> <Mount Point>\n");
		return EXIT_FAILURE;
	}
	
	vfs_data = malloc(sizeof(struct vfs_state));
	if(vfs_data == NULL){
		perror("main calloc");
		return EXIT_FAILURE;
	}
	//store the mountpt
	vfs_data->mountpt = realpath(argv[argc-1], NULL);
	argv[argc-1] = NULL;
	argc--;	
	//store the mirrordir
	vfs_data->mirrordir = realpath(argv[argc-1], NULL);
	argv[argc-1] = NULL;
	argc--;
	//store key phrase
	vfs_data->key = argv[argc-1];
	argv[argc-1] = NULL;
	//provide fuse the program name and mount pt
	if(argc > 2){
		argv[argc-1] = vfs_data->mountpt; //fill in last arg with mountpt 
		//keep other optional fuse args
	}
	else argv[1] = vfs_data->mountpt;
	//printf("mirrordir %s and mountpt %s\n", vfs_data->mirrordir, vfs_data->mountpt);
	
	return fuse_main(argc, argv, &xmp_oper, vfs_data);
}
