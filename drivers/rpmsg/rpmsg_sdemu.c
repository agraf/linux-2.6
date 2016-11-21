/*
 * PRU Remote Processor Messaging Driver
 *
 * Copyright (C) 2015 Texas Instruments, Inc.
 *
 * Jason Reeder <jreeder@ti.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <asm/cacheflush.h>
#include <linux/kernel.h>
#include <linux/rpmsg.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/cdev.h>
#include <linux/module.h>
#include <linux/kfifo.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/remoteproc.h>
#include <linux/crc7.h>
#include <linux/interrupt.h>

#define PRU_MAX_DEVICES				(2)
/* Matches the definition in virtio_rpmsg_bus.c */
#define RPMSG_BUF_SIZE				(512)
#define MAX_FIFO_MSG				(31)
#define FIFO_MSG_SIZE				RPMSG_BUF_SIZE

#define SDEMU_MSG_DBG				' '
#define SDEMU_MSG_SETPINS_CMD_IN		'1'
#define SDEMU_MSG_SETPINS_CMD_OUT		'2'
#define SDEMU_MSG_SETPINS_DAT_IN		'3'
#define SDEMU_MSG_SETPINS_DAT_OUT		'4'
#define SDEMU_MSG_SETPINS_SPI			'5'
#define SDEMU_MSG_SETPINS_RESET			'6'
#define SDEMU_MSG_QUERY_SD_INIT			'I'
#define SDEMU_MSG_SET_SIZE			'S'
#define SDEMU_MSG_PREAD_4BIT			'R'
#define SDEMU_MSG_PWRITE_4BIT			'W'
#define SDEMU_MSG_DONE				'\0'

/**
 * struct rpmsg_sdemu_dev - Structure that contains the per-device data
 * @rpdev: rpmsg channel device that is associated with this rpmsg_sdemu device
 * @dev: device
 * @cdev: character device
 * @devt: dev_t structure for the rpmsg_sdemu device
 * @rpmsg_sdemu_msg_fifo: kernel fifo used to buffer the messages between user
 *						space and the PRU
 * @rpmsg_sdemu_msg_len: array storing the lengths of each message in the kernel
 *					   fifo
 * @rpmsg_sdemu_msg_idx_rd: kernel fifo read index
 * @rpmsg_sdemu_msg_idx_wr: kernel fifo write index
 * @rpmsg_sdemu_wait_list: wait queue used to implement the poll operation of
 *						 the character device
 *
 * Each rpmsg_sdemu device provides an interface, using an rpmsg channel (rpdev),
 * between a user space character device (cdev) and a PRU core. A kernel fifo
 * (rpmsg_sdemu_msg_fifo) is used to buffer the messages in the kernel that are
 * being passed between the character device and the PRU.
 */
struct rpmsg_sdemu_dev {
	struct rpmsg_channel *rpdev;
	struct device *dev;
	struct cdev cdev;
	bool locked;
	dev_t devt;
	struct kfifo rpmsg_sdemu_msg_fifo;
	u32 rpmsg_sdemu_msg_len[MAX_FIFO_MSG];
	int rpmsg_sdemu_msg_idx_rd;
	int rpmsg_sdemu_msg_idx_wr;
	wait_queue_head_t rpmsg_sdemu_wait_list;

	u64 size;
	int fd;
	char buf[8192];
	void *dmem_fast;
	struct workqueue_struct *wq;
	struct work_struct offload;
};

/**
 * struct virtproc_info - virtual remote processor state
 * @vdev:	the virtio device
 * @rvq:	rx virtqueue
 * @svq:	tx virtqueue
 * @rbufs:	kernel address of rx buffers
 * @sbufs:	kernel address of tx buffers
 * @num_bufs:	total number of buffers for rx and tx
 * @last_sbuf:	index of last tx buffer used
 * @bufs_dma:	dma base addr of the buffers
 * @tx_lock:	protects svq, sbufs and sleepers, to allow concurrent senders.
 *		sending a message might require waking up a dozing remote
 *		processor, which involves sleeping, hence the mutex.
 * @endpoints:	idr of local endpoints, allows fast retrieval
 * @endpoints_lock: lock of the endpoints set
 * @sendq:	wait queue of sending contexts waiting for a tx buffers
 * @sleepers:	number of senders that are waiting for a tx buffer
 * @ns_ept:	the bus's name service endpoint
 *
 * This structure stores the rpmsg state of a given virtio remote processor
 * device (there might be several virtio proc devices for each physical
 * remote processor).
 */
struct virtproc_info {
	struct virtio_device *vdev;
	struct virtqueue *rvq, *svq;
	void *rbufs, *sbufs;
	unsigned int num_bufs;
	int last_sbuf;
	dma_addr_t bufs_dma;
	struct mutex tx_lock;
	struct idr endpoints;
	struct mutex endpoints_lock;
	wait_queue_head_t sendq;
	atomic_t sleepers;
	struct rpmsg_endpoint *ns_ept;
};

static struct class *rpmsg_sdemu_class;
static dev_t rpmsg_sdemu_devt;
static DEFINE_MUTEX(rpmsg_sdemu_lock);
static DEFINE_IDR(minors);

static int rpmsg_sdemu_open(struct inode *inode, struct file *filp)
{
	struct rpmsg_sdemu_dev *prudev;
	int ret = -EBUSY;

	prudev = container_of(inode->i_cdev, struct rpmsg_sdemu_dev, cdev);

	mutex_lock(&rpmsg_sdemu_lock);
	if (!prudev->locked) {
		prudev->locked = true;
		filp->private_data = prudev;
		ret = 0;
	}
	mutex_unlock(&rpmsg_sdemu_lock);

	return ret;
}

static int rpmsg_sdemu_release(struct inode *inode, struct file *filp)
{
	struct rpmsg_sdemu_dev *sdemudev;

	sdemudev = container_of(inode->i_cdev, struct rpmsg_sdemu_dev, cdev);
	mutex_lock(&rpmsg_sdemu_lock);
	sdemudev->locked = false;
	mutex_unlock(&rpmsg_sdemu_lock);
	return 0;
}

static ssize_t rpmsg_sdemu_read(struct file *filp, char *buf, size_t count,
						loff_t *f_pos)
{
	int ret;
	u32 length;
	struct rpmsg_sdemu_dev *prudev;

	prudev = filp->private_data;

	if (kfifo_is_empty(&prudev->rpmsg_sdemu_msg_fifo) &&
						(filp->f_flags & O_NONBLOCK))
			return -EAGAIN;

	ret = wait_event_interruptible(prudev->rpmsg_sdemu_wait_list,
				!kfifo_is_empty(&prudev->rpmsg_sdemu_msg_fifo));
	if (ret)
		return -EINTR;

	ret = kfifo_to_user(&prudev->rpmsg_sdemu_msg_fifo, buf,
		prudev->rpmsg_sdemu_msg_len[prudev->rpmsg_sdemu_msg_idx_rd],
		&length);
	prudev->rpmsg_sdemu_msg_idx_rd =
		(prudev->rpmsg_sdemu_msg_idx_rd + 1) % MAX_FIFO_MSG;

	return ret ? ret : length;
}

static ssize_t rpmsg_sdemu_write(struct file *filp, const __user char *buf, size_t count,
						 loff_t *f_pos)
{
	int ret;
	struct rpmsg_sdemu_dev *prudev;
	void *lbuf[count];

	prudev = filp->private_data;

	if (count > RPMSG_BUF_SIZE - sizeof(struct rpmsg_hdr)) {
		dev_err(prudev->dev, "Data too large for RPMsg Buffer\n");
		return -EINVAL;
	}

	if (copy_from_user(lbuf, buf, count))
		return -EFAULT;

	ret = rpmsg_send(prudev->rpdev, lbuf, count);
	if (ret)
		dev_err(prudev->dev, "rpmsg_send failed: %d\n", ret);

	return ret ? ret : count;
}

static unsigned int rpmsg_sdemu_poll(struct file *filp,
						struct poll_table_struct *wait)
{
	int mask;
	struct rpmsg_sdemu_dev *prudev;

	prudev = filp->private_data;

	poll_wait(filp, &prudev->rpmsg_sdemu_wait_list, wait);

	mask = POLLOUT | POLLWRNORM;

	if (!kfifo_is_empty(&prudev->rpmsg_sdemu_msg_fifo))
		mask |= POLLIN | POLLRDNORM;

	return mask;
}

#define SDEMU_IO		0x42
#define SDEMU_SET_SIZE		_IOR(SDEMU_IO,   0x00, __u64)
#define SDEMU_SET_FD		_IOR(SDEMU_IO,   0x01, __u64)

static long rpmsg_sdemu_ioctl(struct file *filp,
			   unsigned int ioctl, unsigned long arg)
{
	struct rpmsg_sdemu_dev *prudev = filp->private_data;
	void __user *argp = (void __user *)arg;
	int r = -EINVAL;
	u64 tmp64;

	switch (ioctl) {
	case SDEMU_SET_SIZE:
		r = -EFAULT;
		if (copy_from_user(&tmp64, argp, sizeof(__u64)))
			goto out;

		prudev->size = tmp64;
		break;
	case SDEMU_SET_FD:
		r = -EFAULT;
		if (copy_from_user(&tmp64, argp, sizeof(__u64)))
			goto out;

		prudev->fd = tmp64;
		break;
	}

out:
	return r;
}

static const struct file_operations rpmsg_sdemu_fops = {
	.owner = THIS_MODULE,
	.open = rpmsg_sdemu_open,
	.read = rpmsg_sdemu_read,
	.release = rpmsg_sdemu_release,
	.write = rpmsg_sdemu_write,
	.poll = rpmsg_sdemu_poll,
	.unlocked_ioctl = rpmsg_sdemu_ioctl,
};

/**************** PRU callbacks ****************/

static void rpmsg_sdemu_set_pins(struct rpmsg_sdemu_dev *prudev, char cmd)
{
	extern void *pinctl;

	switch (cmd) {
	case SDEMU_MSG_SETPINS_CMD_IN:
		/* Set CMD pinmux to INPUT */
		writel(0x2e, pinctl + 0x194); /* CMD */
		break;
	case SDEMU_MSG_SETPINS_CMD_OUT:
		/* Set CMD pinmux to OUTPUT */
		writel(0x05, pinctl + 0x194); /* CMD */
		break;
	case SDEMU_MSG_SETPINS_DAT_IN:
		/* Set DAT pinmux to INPUT */
		writel(0x2e, pinctl + 0xe0); /* DAT0 (pru1) */
		writel(0x2e, pinctl + 0xe4); /* DAT1 (pru1) */
		writel(0x2e, pinctl + 0xe8); /* DAT2 (pru1) */
		writel(0x2e, pinctl + 0xec); /* DAT3 (pru1) */
		break;
	case SDEMU_MSG_SETPINS_DAT_OUT:
		/* Set DAT pinmux to OUTPUT */
		writel(0x05, pinctl + 0xe0); /* DAT0 (pru1) */
		writel(0x05, pinctl + 0xe4); /* DAT1 (pru1) */
		writel(0x05, pinctl + 0xe8); /* DAT2 (pru1) */
		writel(0x05, pinctl + 0xec); /* DAT3 (pru1) */
		break;
	case SDEMU_MSG_SETPINS_SPI:
		/* Set DAT pinmux to OUTPUT */
		writel(0x33, pinctl + 0x190); /* CLK  (pru0) */
		writel(0x33, pinctl + 0x194); /* CMD  (pru0) */
		writel(0x13, pinctl + 0x198); /* DAT0 (pru0) */
		writel(0x33, pinctl + 0x19c); /* DAT3 (pru0) */
		break;
	case SDEMU_MSG_SETPINS_RESET:
		/* Set all pinmux to INPUT */
		writel(0x2e, pinctl + 0x190); /* CLK  (pru0) */
		writel(0x2e, pinctl + 0x194); /* CMD  (pru0) */
		writel(0x2e, pinctl + 0x198); /* DAT0 (pru0) */
		writel(0x2e, pinctl + 0x19c); /* DAT3 (pru0) */
		writel(0x2e, pinctl + 0x3c);  /* CLK  (pru1) */
		writel(0x2e, pinctl + 0xe0);  /* DAT0 (pru1) */
		writel(0x2e, pinctl + 0xe4);  /* DAT1 (pru1) */
		writel(0x2e, pinctl + 0xe8);  /* DAT2 (pru1) */
		writel(0x2e, pinctl + 0xec);  /* DAT3 (pru1) */
		break;
	}
}

static void rpmsg_sdemu_set_size(struct rpmsg_sdemu_dev *prudev, u32 ptr)
{
	struct rproc *rp = rproc_vdev_to_rproc_safe(prudev->rpdev->vrp->vdev);
	u64 *va;
	u64 size = prudev->size;

	/* Set SD card size in device address space */
	va = rproc_da_to_va(rp, ptr, sizeof(*va), 0);

	if (!size)
		size = 0x1234ULL * 1024 * 1024;

	writel(size, va);
	writel(size >> 32, va + 4);

printk(KERN_INFO "Setting size at %x/%p to %llx\n", ptr, va, size);
}

static void rpmsg_sdemu_pread(struct rpmsg_sdemu_dev *prudev, u32 ptr,
			       u64 addr, u32 len)
{
	struct rproc *rp = rproc_vdev_to_rproc_safe(prudev->rpdev->vrp->vdev);
	struct fd f;
	u64 *va;
	char *buf = prudev->buf;
	int i, j, ret = 0;
	u8 crc7[4], out_crc7[4];

	if (len > 8192)
		return;

	/* Set SD card size in device address space */
	va = rproc_da_to_va(rp, ptr, len + 1, 0);

	f = fdget(prudev->fd);
	if (f.file) {
		if (f.file->f_mode & FMODE_PREAD)
			ret = vfs_read(f.file, buf, len, &addr);
		fdput(f);
	}

	WARN_ON(len != ret);

	while (len >= 512) {
		memcpy(va, buf, 512);

		/* Calculate CRC7 for every DAT line */
		for (i = 0; i < 4; i++) {
			char stream[512 / 4];
			u8 mask1 = 0x80 >> i;
			u8 mask2 = 0x08 >> i;

			for (j = 0; i < (512 / 4); j++) {
				stream[j] = (buf[j * 4 + 0] & mask1) ? 0x80 : 0x00 |
					    (buf[j * 4 + 0] & mask2) ? 0x40 : 0x00 |
					    (buf[j * 4 + 1] & mask1) ? 0x20 : 0x00 |
					    (buf[j * 4 + 1] & mask2) ? 0x10 : 0x00 |
					    (buf[j * 4 + 2] & mask1) ? 0x08 : 0x00 |
					    (buf[j * 4 + 2] & mask2) ? 0x04 : 0x00 |
					    (buf[j * 4 + 3] & mask1) ? 0x02 : 0x00 |
					    (buf[j * 4 + 3] & mask2) ? 0x01 : 0x00;
			}

			crc7[i] = crc7_be(0, buf, 512 / 4) | 1;
		}

		for (i = 0; i < 4; i++) {
			u8 mask = 0x80 >> (i * 2);
			out_crc7[i] = (crc7[3] & mask)        ? 0x80 : 0x00 |
				      (crc7[2] & mask)        ? 0x40 : 0x00 |
				      (crc7[1] & mask)        ? 0x20 : 0x00 |
				      (crc7[0] & mask)        ? 0x10 : 0x00 |
				      (crc7[3] & (mask >> 1)) ? 0x08 : 0x00 |
				      (crc7[2] & (mask >> 1)) ? 0x04 : 0x00 |
				      (crc7[1] & (mask >> 1)) ? 0x02 : 0x00 |
				      (crc7[0] & (mask >> 1)) ? 0x01 : 0x00;
		}

		memcpy(va + 512, out_crc7, 4);

		/* Make available to PRU */
		__cpuc_flush_dcache_area(va, 512 + 4);

		/* Off to the next sector */
		buf += 512;
		va += 512 + 4;
	}
}

static void rpmsg_sdemu_pwrite(struct rpmsg_sdemu_dev *prudev, u32 ptr,
			        u64 addr, u32 len)
{
}

static void sdemu_work(struct work_struct *work)
{
	struct rpmsg_sdemu_dev *prudev =
			 container_of(work, struct rpmsg_sdemu_dev, offload);
	void *data = prudev->dmem_fast;
	u8 cmd = readb(data);
	u32 ptr = readl(data + 1);
	u64 addr = readl(data + 5) | ((u64)readl(data + 9) << 32);
	u32 length = readl(data + 13);
	bool handled = false;

	switch (cmd) {
	case SDEMU_MSG_PREAD_4BIT:
		rpmsg_sdemu_pread(prudev, ptr, addr, length);
		handled = true;
		break;
	case SDEMU_MSG_PWRITE_4BIT:
		rpmsg_sdemu_pwrite(prudev, ptr, addr, length);
		handled = true;
		break;
	}

	if (handled)
		writeb(SDEMU_MSG_DONE, prudev->dmem_fast);
}

extern void pru_rproc_set_fast_interrupt(struct rproc *rproc,
					 irqreturn_t (*cb) (int, void *),
					 void *opaque);

/* This callback gets invoked from IRQ context! */
static irqreturn_t sdemu_fast_interrupt(int irq, void *opaque)
{
	struct rpmsg_sdemu_dev *prudev = opaque;
	void *data = prudev->dmem_fast;
	u8 cmd = readb(data);
	u32 ptr;
	bool handled = false;

	switch (cmd) {
	case SDEMU_MSG_SETPINS_CMD_IN:
	case SDEMU_MSG_SETPINS_CMD_OUT:
	case SDEMU_MSG_SETPINS_DAT_IN:
	case SDEMU_MSG_SETPINS_DAT_OUT:
	case SDEMU_MSG_SETPINS_SPI:
	case SDEMU_MSG_SETPINS_RESET:
		rpmsg_sdemu_set_pins(prudev, cmd);
		handled = true;
		break;
	case SDEMU_MSG_SET_SIZE:
		ptr = readl(data + 1);
		rpmsg_sdemu_set_size(prudev, ptr);
		handled = true;
		break;
	case SDEMU_MSG_PREAD_4BIT:
	case SDEMU_MSG_PWRITE_4BIT:
		queue_work(prudev->wq, &prudev->offload);
		break;
	}

	if (handled)
		writeb(SDEMU_MSG_DONE, prudev->dmem_fast);

	return IRQ_HANDLED;
}

static void rpmsg_sdemu_cb(struct rpmsg_channel *rpdev, void *data, int len,
					void *priv, u32 src)
{
	struct rpmsg_sdemu_dev *prudev;
	u32 length;

	if (!len)
		return;

	prudev = dev_get_drvdata(&rpdev->dev);

	if (kfifo_avail(&prudev->rpmsg_sdemu_msg_fifo) < len) {
		dev_err(&rpdev->dev, "Not enough space on the FIFO\n");
		return;
	}

	if ((prudev->rpmsg_sdemu_msg_idx_wr + 1) % MAX_FIFO_MSG ==
		prudev->rpmsg_sdemu_msg_idx_rd) {
		dev_err(&rpdev->dev, "Message length table is full\n");
		return;
	}

	length = kfifo_in(&prudev->rpmsg_sdemu_msg_fifo, data, len);
	prudev->rpmsg_sdemu_msg_len[prudev->rpmsg_sdemu_msg_idx_wr] = length;
	prudev->rpmsg_sdemu_msg_idx_wr =
		(prudev->rpmsg_sdemu_msg_idx_wr + 1) % MAX_FIFO_MSG;

	wake_up_interruptible(&prudev->rpmsg_sdemu_wait_list);

	return;
}

static int rpmsg_sdemu_probe(struct rpmsg_channel *rpdev)
{
	int ret;
	struct rpmsg_sdemu_dev *prudev;
	int minor_got;

	prudev = devm_kzalloc(&rpdev->dev, sizeof(*prudev), GFP_KERNEL);
	if (!prudev) {
		dev_err(&rpdev->dev, "Unable to allocate kernel memory for the rpmsg_sdemu device\n");
		return -ENOMEM;
	}

	mutex_lock(&rpmsg_sdemu_lock);
	minor_got = idr_alloc(&minors, prudev, 0, PRU_MAX_DEVICES, GFP_KERNEL);
	mutex_unlock(&rpmsg_sdemu_lock);
	if (minor_got < 0) {
		ret = minor_got;
		dev_err(&rpdev->dev, "Failed to get a minor number for the rpmsg_sdemu device: %d\n",
			ret);
		goto fail_alloc_minor;
	}

	prudev->devt = MKDEV(MAJOR(rpmsg_sdemu_devt), minor_got);

	cdev_init(&prudev->cdev, &rpmsg_sdemu_fops);
	prudev->cdev.owner = THIS_MODULE;
	ret = cdev_add(&prudev->cdev, prudev->devt, 1);
	if (ret) {
		dev_err(&rpdev->dev, "Unable to add cdev for the rpmsg_sdemu device\n");
		goto fail_add_cdev;
	}

	prudev->dev = device_create(rpmsg_sdemu_class, &rpdev->dev, prudev->devt,
		NULL, "rpmsg_sdemu" "%d", rpdev->dst);
	if (IS_ERR(prudev->dev)) {
		dev_err(&rpdev->dev, "Unable to create the rpmsg_sdemu device\n");
		ret = PTR_ERR(prudev->dev);
		goto fail_create_device;
	}

	prudev->rpdev = rpdev;

	ret = kfifo_alloc(&prudev->rpmsg_sdemu_msg_fifo,
		MAX_FIFO_MSG * FIFO_MSG_SIZE, GFP_KERNEL);
	if (ret) {
		dev_err(&rpdev->dev, "Unable to allocate fifo for the rpmsg_sdemu device\n");
		goto fail_alloc_fifo;
	}

	init_waitqueue_head(&prudev->rpmsg_sdemu_wait_list);

	dev_set_drvdata(&rpdev->dev, prudev);

	{
	struct rproc *rp = rproc_vdev_to_rproc_safe(prudev->rpdev->vrp->vdev);

	/* Remember VA for shared ram region */
	prudev->dmem_fast = rproc_da_to_va(rp, 0x1f80, 0x80, 0);

	/* Register fast interrupt handler */
	pru_rproc_set_fast_interrupt(rp, sdemu_fast_interrupt, prudev);
	}

	prudev->wq = create_singlethread_workqueue(dev_name(prudev->dev));
	INIT_WORK(&prudev->offload, sdemu_work);

	dev_info(&rpdev->dev, "new rpmsg_sdemu device: /dev/rpmsg_sdemu%d",
		 rpdev->dst);

	return 0;

fail_alloc_fifo:
	device_destroy(rpmsg_sdemu_class, prudev->devt);
fail_create_device:
	cdev_del(&prudev->cdev);
fail_add_cdev:
	mutex_lock(&rpmsg_sdemu_lock);
	idr_remove(&minors, minor_got);
	mutex_unlock(&rpmsg_sdemu_lock);
fail_alloc_minor:
	return ret;
}

static void rpmsg_sdemu_remove(struct rpmsg_channel *rpdev)
{
	struct rpmsg_sdemu_dev *prudev;

	prudev = dev_get_drvdata(&rpdev->dev);

	kfifo_free(&prudev->rpmsg_sdemu_msg_fifo);
	device_destroy(rpmsg_sdemu_class, prudev->devt);
	cdev_del(&prudev->cdev);
	mutex_lock(&rpmsg_sdemu_lock);
	idr_remove(&minors, MINOR(prudev->devt));
	mutex_unlock(&rpmsg_sdemu_lock);
}

/* .name matches on RPMsg Channels and causes a probe */
static const struct rpmsg_device_id rpmsg_driver_pru_id_table[] = {
	{ .name	= "rpmsg-sdemu" },
	{ },
};
MODULE_DEVICE_TABLE(rpmsg, rpmsg_driver_pru_id_table);

static struct rpmsg_driver rpmsg_sdemu_driver = {
	.drv.name	= KBUILD_MODNAME,
	.drv.owner	= THIS_MODULE,
	.id_table	= rpmsg_driver_pru_id_table,
	.probe		= rpmsg_sdemu_probe,
	.callback	= rpmsg_sdemu_cb,
	.remove		= rpmsg_sdemu_remove,
};

static int __init rpmsg_sdemu_init(void)
{
	int ret;

	rpmsg_sdemu_class = class_create(THIS_MODULE, "rpmsg_sdemu");
	if (IS_ERR(rpmsg_sdemu_class)) {
		pr_err("Unable to create class\n");
		ret = PTR_ERR(rpmsg_sdemu_class);
		goto fail_create_class;
	}

	ret = alloc_chrdev_region(&rpmsg_sdemu_devt, 0, PRU_MAX_DEVICES,
							  "rpmsg_sdemu");
	if (ret) {
		pr_err("Unable to allocate chrdev region\n");
		goto fail_alloc_region;
	}

	ret = register_rpmsg_driver(&rpmsg_sdemu_driver);
	if (ret) {
		pr_err("Unable to register rpmsg driver");
		goto fail_register_rpmsg_driver;
	}

	return 0;

fail_register_rpmsg_driver:
	unregister_chrdev_region(rpmsg_sdemu_devt, PRU_MAX_DEVICES);
fail_alloc_region:
	class_destroy(rpmsg_sdemu_class);
fail_create_class:
	return ret;
}

static void __exit rpmsg_sdemu_exit(void)
{
	unregister_rpmsg_driver(&rpmsg_sdemu_driver);
	idr_destroy(&minors);
	mutex_destroy(&rpmsg_sdemu_lock);
	class_destroy(rpmsg_sdemu_class);
	unregister_chrdev_region(rpmsg_sdemu_devt, PRU_MAX_DEVICES);
}

module_init(rpmsg_sdemu_init);
module_exit(rpmsg_sdemu_exit);

MODULE_AUTHOR("Alexander Graf <agraf@suse.de>");
MODULE_ALIAS("rpmsg:rpmsg-sdemu");
MODULE_DESCRIPTION("SDemu host driver");
MODULE_LICENSE("GPL v2");
