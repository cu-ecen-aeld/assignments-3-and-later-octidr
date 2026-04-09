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
#include <linux/fs.h> // file_operations
#include "aesdchar.h"
#include "aesd_ioctl.h"
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Your Name Here"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

loff_t aesd_llseek(struct file *filp, loff_t off, int whence)
{
    loff_t newpos;
    struct aesd_dev *dev = filp->private_data;
    size_t total_size = 0;
    int i;

    mutex_lock(&dev->lock);

    for (i = 0; i < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; i++) {
        total_size += dev->buffer.entry[i].size;
    }

    switch (whence) {
    case SEEK_SET:
        newpos = off;
        break;
    case SEEK_CUR:
        newpos = filp->f_pos + off;
        break;
    case SEEK_END:
        newpos = total_size + off;
        break;
    default:
        mutex_unlock(&dev->lock);
        return -EINVAL;
    }

    if (newpos < 0 || newpos > total_size) {
        mutex_unlock(&dev->lock);
        return -EINVAL;
    }

    filp->f_pos = newpos;
    mutex_unlock(&dev->lock);
    return newpos;
}

long aesd_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct aesd_seekto seekto;
    struct aesd_dev *dev = filp->private_data;
    loff_t newpos = 0;
    uint32_t i;
    uint32_t index;

    if (cmd != AESDCHAR_IOCSEEKTO)
        return -EINVAL;

    if (copy_from_user(&seekto, (const void __user *)arg, sizeof(seekto)))
        return -EFAULT;

    mutex_lock(&dev->lock);

    if (seekto.write_cmd >= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED) {
        mutex_unlock(&dev->lock);
        return -EINVAL;
    }

    index = (dev->buffer.out_offs + seekto.write_cmd) %
            AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;

    if (seekto.write_cmd_offset >= dev->buffer.entry[index].size) {
        mutex_unlock(&dev->lock);
        return -EINVAL;
    }

    for (i = 0; i < seekto.write_cmd; i++) {
        uint32_t idx = (dev->buffer.out_offs + i) %
                       AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
        newpos += dev->buffer.entry[idx].size;
    }

    newpos += seekto.write_cmd_offset;
    filp->f_pos = newpos;

    mutex_unlock(&dev->lock);
    return 0;
}

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");

    filp->private_data = &aesd_device;

    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");

    filp->private_data = NULL;

    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);

    struct aesd_dev *dev = filp->private_data;
    mutex_lock(&dev->lock);

    size_t entry_offset;
    struct aesd_buffer_entry *entry;

    entry = aesd_circular_buffer_find_entry_offset_for_fpos(
        &dev->buffer,
        *f_pos,
        &entry_offset
    );

    if (!entry) {
        retval = 0;
        goto out;
    }

    size_t bytes_available = entry->size - entry_offset;
    size_t bytes_to_copy = min(count, bytes_available);

    if (copy_to_user(buf, entry->buffptr + entry_offset, bytes_to_copy)) {
        retval = -EFAULT;
        goto out;
    }

    *f_pos += bytes_to_copy;
    retval = bytes_to_copy;

out:
    mutex_unlock(&dev->lock);
    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
    
    struct aesd_dev *dev = filp->private_data;
    mutex_lock(&dev->lock);

    char *kbuf = kmalloc(count, GFP_KERNEL);
    if (!kbuf) {
        retval = -ENOMEM;
        goto out;
    }

    if (copy_from_user(kbuf, buf, count)) {
        kfree(kbuf);
        retval = -EFAULT;
        goto out;
    }

    size_t new_size = dev->entry.size + count;

    char *newbuf = krealloc(dev->entry.buffptr, new_size, GFP_KERNEL);
    if (!newbuf) {
        kfree(kbuf);
        retval = -ENOMEM;
        goto out;
    }

    memcpy(newbuf + dev->entry.size, kbuf, count);
    dev->entry.buffptr = newbuf;
    dev->entry.size = new_size;

    kfree(kbuf);

    if (memchr(dev->entry.buffptr, '\n', dev->entry.size)) {
        if (dev->buffer.full) {
            kfree(dev->buffer.entry[dev->buffer.in_offs].buffptr);
        }

        aesd_circular_buffer_add_entry(
            &dev->buffer,
            &dev->entry
        );

        // reset partial buffer
        dev->entry.buffptr = NULL;
        dev->entry.size = 0;
    }

    retval = count;

    out:
    mutex_unlock(&dev->lock);
    return retval;
}

struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
    .llseek = aesd_llseek,
    .unlocked_ioctl = aesd_ioctl,
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

    /**
     * TODO: initialize the AESD specific portion of the device
     */
    mutex_init(&aesd_device.lock);
    aesd_circular_buffer_init(&aesd_device.buffer);
    aesd_device.write_buffer = NULL;
    aesd_device.write_buffer_size = 0;

    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    struct aesd_buffer_entry *entry;
    uint8_t i;

    for (i = 0; i < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; i++) {
        entry = &aesd_device.buffer.entry[i];
        kfree(entry->buffptr);
    }

    kfree(aesd_device.entry.buffptr);
    mutex_destroy(&aesd_device.lock);

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
