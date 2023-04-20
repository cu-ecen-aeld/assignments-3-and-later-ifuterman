/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/fs.h> // file_operations
#include "aesdchar.h"
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Iosif Futerman"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
	struct aesd_dev* dev;
	dev = NULL;
  PDEBUG("open");
    /**
     * TODO: handle open
     */
  dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
  filp->private_data = dev;
  return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
	PDEBUG("release");
    /**
     * TODO: handle release
     */
//	filp->private_data = NULL;
  return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
  ssize_t retval;
  struct aesd_dev *dev;
	struct aesd_buffer_entry* entry;
	size_t offset;
	size_t copied;
	copied = 0;
  retval = 0;
	offset = 0;
  PDEBUG("read %zu bytes with offset %lld",count,*f_pos);

  dev = (struct aesd_dev *)filp->private_data;
	retval = mutex_lock_interruptible(&dev->mutex_lock);
	entry = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->circular_buffer, *f_pos, &offset);
	if(!retval){
		return -ERESTARTSYS;
	}
	if(entry == NULL){
		mutex_unlock(&dev->mutex_lock);
		return 0;
	}
	copied = copy_to_user(buf, entry->buffptr + offset, entry->size - offset);
	mutex_unlock(&dev->mutex_lock);
	*f_pos += copied;
  PDEBUG("readed %zu bytes",copied);
  return copied;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
  ssize_t retval = -ENOMEM;
	struct aesd_dev *dev;
	struct aesd_buffer_entry entry;
	size_t copied;
	copied = 0;
	dev = NULL;
  PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle write
     */
	dev = (struct aesd_dev *)filp->private_data;
	
	entry.buffptr = kmalloc(count, GFP_KERNEL);
	if(!entry.buffptr){
	  PDEBUG("WRITE!KMALLOC FAILED");
		return retval;
	}
	copied = copy_from_user((void*)entry.buffptr, buf, count);
  PDEBUG("WRITE! copied %zu bytes buf: %s",count,entry.buffptr);
	entry.size = copied;

	retval = mutex_lock_interruptible(&dev->mutex_lock);
	if(!retval){
		kfree(entry.buffptr);
		return -ERESTARTSYS;
	}
	if(dev->circular_buffer.entry[dev->circular_buffer.in_offs].buffptr){
		kfree(dev->circular_buffer.entry[dev->circular_buffer.in_offs].buffptr);
	}
	aesd_circular_buffer_add_entry(&dev->circular_buffer, &entry);
	mutex_unlock(&dev->mutex_lock);
  PDEBUG("writed %zu bytes",copied);
  *f_pos += copied;
	return copied;
}
struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));


		mutex_init(&aesd_device.mutex_lock);
		aesd_circular_buffer_init(&aesd_device.circular_buffer);
    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
	uint8_t index;
	struct aesd_buffer_entry *entry;
	dev_t devno = MKDEV(aesd_major, aesd_minor);

	cdev_del(&aesd_device.cdev);


	AESD_CIRCULAR_BUFFER_FOREACH(entry,&aesd_device.circular_buffer,index) {
		if(entry->buffptr){
			kfree(entry->buffptr);
		}
	}  
	mutex_destroy(&aesd_device.mutex_lock);
  unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
