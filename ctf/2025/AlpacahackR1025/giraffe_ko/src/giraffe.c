#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ptr-yudai");
MODULE_DESCRIPTION("giraffe.ko - AlpacaHack Round 10 Pwn");

#define DEVICE_NAME "giraffe"

#define CACHE_NAME "giraffe_cache"
#define BUF_SIZE 0x20

static struct kmem_cache *giraffe_cache = NULL;

static int module_open(struct inode *inode, struct file *filp) {
  filp->private_data = kmem_cache_alloc(giraffe_cache, GFP_KERNEL);
  if (!filp->private_data)
    return -ENOMEM;
  else
    return 0;
}

static int module_close(struct inode *inode, struct file *filp) {
  kmem_cache_free(giraffe_cache, filp->private_data);
  return 0;
}

static ssize_t module_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos) {
  char tmp[BUF_SIZE+1] = { 0 };
  size_t datalen;

  strcpy(tmp, filp->private_data);

  datalen = strlen(tmp);
  count = count > datalen ? datalen : count;
  if (copy_to_user(buf, tmp, count))
    return -EINVAL;

	return count;
}

static ssize_t module_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos) {
  char tmp[BUF_SIZE+1] = { 0 };
  count = count > BUF_SIZE ? BUF_SIZE : count;

  if (copy_from_user(tmp, buf, count))
    return -EINVAL;

  strcpy(filp->private_data, tmp);

	return strlen(tmp);
}

static struct file_operations module_fops = {
  .owner   = THIS_MODULE,
  .open    = module_open,
  .release = module_close,
  .read    = module_read,
  .write   = module_write,
};

static dev_t dev_id;
static struct cdev c_dev;

static void giraffe_obj_init(void *addr) {
  memset(addr, 0, BUF_SIZE);
}

static int __init module_initialize(void) {
  giraffe_cache = kmem_cache_create(CACHE_NAME, BUF_SIZE, 0, 0, giraffe_obj_init);
  if (!giraffe_cache)
    return -ENOMEM;

  if (alloc_chrdev_region(&dev_id, 0, 1, DEVICE_NAME)) {
    kmem_cache_destroy(giraffe_cache);
    return -EBUSY;
  }

  cdev_init(&c_dev, &module_fops);
  c_dev.owner = THIS_MODULE;

  if (cdev_add(&c_dev, dev_id, 1)) {
    unregister_chrdev_region(dev_id, 1);
    kmem_cache_destroy(giraffe_cache);
    return -EBUSY;
  }

  return 0;
}

static void __exit module_cleanup(void) {
  cdev_del(&c_dev);
  unregister_chrdev_region(dev_id, 1);
  kmem_cache_destroy(giraffe_cache);
}

module_init(module_initialize);
module_exit(module_cleanup);
