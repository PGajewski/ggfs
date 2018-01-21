#include <linux/init.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/gpio.h>

MODULE_AUTHOR("Pawel Gajewski, SciTeeX Company");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Simple File System to gathering information from Onion IoT pin (or another Linux devices)");
MODULE_VERSION("0.3");
MODULE_INFO(intree, "Y");

#define GGFS_MAGIC	0xa647361

////////////////////////////////////Data types//////////////////////////////////////////////
enum state {low, high};
enum direction {in, out};

// Time 
struct cycle_time
{
    time_t time;
    struct list_head list;
};

struct ggfs_gpio
{
    bool is_available;
	bool is_free;
	bool is_confirmation;
    unsigned int gpio_num;
	unsigned int confirm_gpio;
    unsigned int irq_number;
    time_t last_event_time;
	enum state state;
	enum direction direction;
	struct mutex mut;
    struct cycle_time time_list;
} ggfs_gpio;
///////////////////////////////GPIo functions//////////////////////////////////

/**
 * Handlers for GPIO in input mode.
 */

//Handler for rising input.
static irq_handler_t ggfs_gpio_rising_handler(struct ggfs_gpio* gpio){

    //Start counting time.
    struct timespec now;
    getnstimeofday(&now);
    
    gpio->last_event_time = now.tv_sec * 1000 + (now.tv_nsec / 1000000);

    return (irq_handler_t) IRQ_HANDLED;

}

//Handler for falling input.
static irq_handler_t ggfs_gpio_falling_handler(struct ggfs_gpio* gpio){

    //Stop counting time.
    struct timespec now;
    getnstimeofday(&now);
    
    //Create new list object.
    struct cycle_time* new_time;
    new_time = kmalloc(sizeof(*new_time), GFP_KERNEL);


    
    time_t end_time = now.tv_sec * 1000 + (now.tv_nsec / 1000000);
        
    //Count and add time to total time and time table.
    time_t process_time = end_time - gpio->last_event_time;
    new_time->time = process_time;
    
    //Add a list node.
    list_add_tail(&new_time->list, &gpio->time_list.list);

    //Add new last time event.
    gpio->last_event_time = end_time;
    
    //Print times
    printk(KERN_INFO "Gajos GPIO File System: Last operation time: %d msec. Total time: %d msec", process_time, total_time);
    
    return (irq_handler_t) IRQ_HANDLED;      // Announce that the IRQ has been handled correctly

}

static irq_handler_t ggfs_gpio_irq_handler(unsigned int irq, void *dev_id, struct pt_regs *regs){
    
    //Cast dev pointer.
    struct ggfs_gpio this_gpio = (ggfs_gpio) dev_id;
    
     //Set confirm gpio value.
    bool gpio_value = gpio_get_value(this_gpio->gpio_num);
    gpio_set_value(this_gpio->confirm_gpio, this_gpio->gpio_num);
    
    //Get IRQ flag
    printk(KERN_INFO "Gajos GPIO File System: Interrupt on %d! Value: %d", this_gpio->gpio_num, this_gpio->confirm_gpio);
    irq_handler_t result;
    
    switch(gpio_get_value(module_gpio))
    {
        case 0: result = ggfs_gpio_falling_handler(this_gpio); break;
        case 1: result = ggfs_gpio_rising_handler(this_gpio); break;
    }
    return result;
    
}

static int set_gpio_direction(ggfs_gpio* gpio, enum direction new_direction)
{
    printk(KERN_ALERT "DEBUG: set_gpio_direction");
    
    printk(KERN_ALERT "GGFS: changing state on gpio %d", gpio->gpio_num);
    
    if(new_direction == input)
    {
        char gpio_handler_name[15];
        sprintf(gpio_handler_name, "gpio%d_handler", module_gpio);
        
        gpio_direction_input(gpio->gpio_num);
        
        //Set handlers.
        result = request_irq(irq_number,                                // The interrupt number requested
                    (irq_handler_t) ggfs_gpio_irq_handler,              // The pointer to the handler function below
                    IRQF_TRIGGER_RISING | IRQF_TRIGGER_FALLING,         // Interrupt on rising edge (input active)
                    gpio_handler_name,                                  // Used in /proc/interrupts to identify the owner
                    gpio);
        
        printk(KERN_ALERT "GGFS: set_gpio_direction");
        
        //Check adding handler error.
        if(result)
            return result;
    }
    else
    {
        gpio_direction_output(gpio->gpio_num,0);
        return 0;
    }
    
}

static void init_gpio(ggfs_gpio* gpio, unsigned int gpio_number)
{
    //Check gpio.
    if(!gpio_request(gpio_number, "ggfs"))
    {
        return -EPERM;
    }
    
    //Check handlers.
    
    gpio->gpio_num = gpio_number;
    gpio->confirm_gpio = 0;
    
    //Get irq number.
    gpio->irq_number = gpio_to_irq(gpio_number);
    
    //Set direction
    set_gpio_direction(gpio, input);
    
    //Init semathore.
    mutex_init(&mut);
    
    //Init time list.
    INIT_LIST_HEAD(&gpio->time_list.list);
        
}


///////////////////////////////File operations funcions////////////////////////
static ssize_t value_file_write(struct file *file, const char __user *buf,
			     size_t len, loff_t *ptr)
{
    return 0;
}

static ssize_t value_file_read(struct file *file, char __user *buf,
			    size_t len, loff_t *ptr)
{
	return 0;
}


static int value_file_open(struct inode *inode, struct file *file)
{
	struct ggfs_gpio *gpio = (struct ggfs_gpio*)inode->i_private;

    //Try to allocate mutex.
    if(!mutex_trylock(&gpio->mut)){

      printk(KERN_ALERT "SciTeeX_GPIO: Device in use by another process");

      return -EBUSY;
   }
   	file->private_data = gpio;

    return 0;
}

static int value_file_release(struct inode *inode, struct file *file)
{
	struct ggfs_gpio *gpio = file->private_data;

    mutex_unlock(&gpio->mut);
    
    return 0;
}

static ssize_t direction_file_write(struct file *file, const char __user *buf,
			     size_t len, loff_t *ptr)
{
    return 0;
}

static ssize_t direction_file_read(struct file *file, char __user *buf,
			    size_t len, loff_t *ptr)
{
	return 0;
}


static int direction_file_open(struct inode *inode, struct file *file)
{
	struct ggfs_gpio *gpio = (struct ggfs_gpio*)inode->i_private;

    //Try to allocate mutex.
    if(!mutex_trylock(&gpio->mut)){

      printk(KERN_ALERT "SciTeeX_GPIO: Device in use by another process");

      return -EBUSY;
   }
   	file->private_data = gpio;

    return 0;
}

static int direction_file_release(struct inode *inode, struct file *file)
{
	struct ggfs_gpio *gpio = file->private_data;

    mutex_unlock(&gpio->mut);
    
    return 0;
}

static ssize_t total_time_file_write(struct file *file, const char __user *buf,
			     size_t len, loff_t *ptr)
{
    return 0;
}

static ssize_t total_time_file_read(struct file *file, char __user *buf,
			    size_t len, loff_t *ptr)
{
	return -0;
}


static int total_time_file_open(struct inode *inode, struct file *file)
{
	struct ggfs_gpio *gpio = (struct ggfs_gpio*)inode->i_private;

    //Try to allocate mutex.
    if(!mutex_trylock(&gpio->mut)){

      printk(KERN_ALERT "SciTeeX_GPIO: Device in use by another process");

      return -EBUSY;
   }
   	file->private_data = gpio;

    return 0;
}

static int total_time_file_release(struct inode *inode, struct file *file)
{
	struct ggfs_gpio *gpio = file->private_data;

    mutex_unlock(&gpio->mut);
    
    return 0;
}


static ssize_t time_list_file_read(struct file *file, char __user *buf,
			    size_t len, loff_t *ptr)
{
	return 0;
}


static int time_list_file_open(struct inode *inode, struct file *file)
{
	struct ggfs_gpio *gpio = (struct ggfs_gpio*)inode->i_private;

    //Try to allocate mutex.
    if(!mutex_trylock(&gpio->mut)){

      printk(KERN_ALERT "SciTeeX_GPIO: Device in use by another process");

      return -EBUSY;
   }
   	file->private_data = gpio;

    return 0;
}

static int time_list_file_release(struct inode *inode, struct file *file)
{
	struct ggfs_gpio *gpio = file->private_data;

    mutex_unlock(&gpio->mut);
    
    return 0;
}

static ssize_t info_file_read(struct file *file, char __user *buf,
			    size_t len, loff_t *ptr)
{
	return 0;
}


static int info_file_open(struct inode *inode, struct file *file)
{
	struct ggfs_gpio *gpio = (struct ggfs_gpio*)inode->i_private;

    //Try to allocate mutex.
    if(!mutex_trylock(&gpio->mut)){

      printk(KERN_ALERT "SciTeeX_GPIO: Device in use by another process");

      return -EBUSY;
   }
   	file->private_data = gpio;

    return 0;
}

static int info_file_release(struct inode *inode, struct file *file)
{

	struct ggfs_gpio *gpio = file->private_data;

    mutex_unlock(&gpio->mut);
    
    return 0;}
///////////////////////////////File operiations////////////////////////////////
//Different file operiations for different files.
static const struct file_operations value_file_operations = {
	.llseek =	no_llseek,
	.open =		value_file_open,
	.write =	value_file_write,
	.read =	    value_file_read,
	.release =	value_file_release,
};

static const struct file_operations direction_file_operations = {
	.llseek =	no_llseek,
	.open =		direction_file_open,
	.write =	direction_file_write,
	.read =	    direction_file_read,
	.release =	direction_file_release,
};

static const struct file_operations total_time_file_operations = {
	.llseek =	no_llseek,
	.open =		total_time_file_open,
	.write =	total_time_file_write,
	.read =	    total_time_file_read,
	.release =	total_time_file_release,
};

static const struct file_operations time_list_file_operations = {
	.llseek =	no_llseek,
	.open =		time_list_file_open,
	.read =	    time_list_file_read,
	.release =	time_list_file_release,
};

static const struct file_operations info_file_operations = {
	.llseek =	no_llseek,
	.open =		info_file_open,
	.read =	    info_file_read,
	.release =	info_file_release,
};

enum ggfs_state {

	GGFS_ACTIVE,

	GGFS_DEACTIVATED,

	GGFS_CLOSING
};

struct ggfs_sb_priv_data
{
	struct ggfs_gpio* gpios_table;
	unsigned int gpios_number;
	unsigned int used_gpios;
} ggfs_sb_priv_data;


struct ggfs_file_perms {
    umode_t				mode;
    kuid_t				uid;
    kgid_t				gid;
} file_perms;

struct ggfs_data {
    
    struct mutex mutex;
    /* reference counter */
    atomic_t			ref;
    /* how many files are opened (EP0 and others) */
    atomic_t			opened;
    
    const char			*dev_name;
	/* Private data for our user.  Managed by user. */
	void				*private_data;
    
    	/*
	 * File system's super block, write once when file system is
	 * mounted.
	 */
	struct super_block		*sb;
    
    /*File permissions */
    struct ggfs_file_perms file_perms;
    
    bool no_disconnect;
};

////////////////////////////////////Module parameters///////////////////////////////////////

// Number of GPIo in device..
static unsigned int device_gpios = 40;

static unsigned int first_gpio = 1;

MODULE_PARM_DESC(device_gpios, "Number of GPIOs in device");
module_param(device_gpios, uint, S_IRUGO);

MODULE_PARM_DESC(first_gpio, "Number of first GPIO in device");
module_param(device_gpios, uint, S_IRUGO);
////////////////////////////////////////////////////////////////////////////////////////////

static struct inode *__must_check
ggfs_sb_make_inode(struct super_block *sb, void *data,
		  const struct file_operations *fops,
		  const struct inode_operations *iops,
		  struct ggfs_file_perms *perms)
{
    printk(KERN_ALERT "DEBUG: ggfs_sb_make_inode");
    
	struct inode *inode;

	inode = new_inode(sb);

	if (likely(inode)) {
		struct timespec ts = current_time(inode);

		inode->i_ino	 = get_next_ino();
		inode->i_mode    = perms->mode;
		inode->i_uid     = perms->uid;
		inode->i_gid     = perms->gid;
		inode->i_atime   = ts;
		inode->i_mtime   = ts;
		inode->i_ctime   = ts;
		inode->i_private = data;
		if (fops)
			inode->i_fop = fops;
		if (iops)
			inode->i_op  = iops;
	}

	return inode;
}

/* Create "regular" file */
static struct dentry *ggfs_sb_create_file(struct super_block *sb,
					const char *name, void *data,
					const struct file_operations *fops)
{
    printk(KERN_ALERT "DEBUG: ggfs_sb_create_file");

    //Create using GPIO.
    struct ggfs_data	*ggfs = sb->s_fs_info;
	struct dentry	*dentry;
	struct inode	*inode;


	dentry = d_alloc_name(sb->s_root, name);
	if (unlikely(!dentry))
		return NULL;

	inode = ggfs_sb_make_inode(sb, data, fops, NULL, &ggfs->file_perms);
	if (unlikely(!inode)) {
		dput(dentry);
		return NULL;
	}
	
	d_add(dentry, inode);
	return dentry;
}

/* Super block */
static const struct super_operations ggfs_sb_operations = {
	.statfs =	simple_statfs,
	.drop_inode =	generic_delete_inode,
};

/* "mount -t functionfs dev_name /dev/function" ends up here */

struct ggfs_sb_fill_data {
	struct ggfs_file_perms perms;
	umode_t root_mode;
	const char *dev_name;
	bool no_disconnect;
	struct ggfs_data *data;
};

/* Init data in data block. */
static struct ggfs_data *ggfs_data_new(void)
{
    printk(KERN_ALERT "DEBUG: ggfs_data_new");
    
    struct ggfs_data *ggfs = kzalloc(sizeof *ggfs, GFP_KERNEL);
	if (unlikely(!ggfs))
		return NULL;

	atomic_set(&ggfs->ref, 1);
	atomic_set(&ggfs->opened, 0);
	//ffs->state = FFS_READ_DESCRIPTORS;
	mutex_init(&ggfs->mutex);

	return ggfs;
}

/* Delete data. */
static void ggfs_data_clear(struct ggfs_data *ggfs)
{
    printk(KERN_ALERT "DEBUG: ggfs_data_clear");

    struct ggfs_sb_priv_data* priv_data = (struct ggfs_sb_priv_data*)ggfs->private_data;
    kfree(priv_data->gpios_table);

}

static void ggfs_data_put(struct ggfs_data *ggfs)
{
    printk(KERN_ALERT "DEBUG: ggfs_data_put");

    
	if (unlikely(atomic_dec_and_test(&ggfs->ref))) {
		pr_info("%s(): freeing\n", __func__);
		ggfs_data_clear(ggfs);
		kfree(ggfs->dev_name);
		kfree(ggfs);
	}
}

static struct ggfs_sb_priv_data* ggfs_init_private_data(unsigned int gpios_number)
{
    int i;
    struct ggfs_sb_priv_data * data;
    data = kmalloc(sizeof(*data), GFP_KERNEL);
    data->gpios_table = kmalloc(sizeof(*data->gpios_table) * gpios_number,GFP_KERNEL);
    for(i = 0; i < gpios_number; ++i)
    {
        init_gpio(data->gpios_table[i], first_gpio + i);
    }
    data->gpios_number = gpios_number;
    data->used_gpios = 0;
    return data;
}


static int ggfs_sb_fill(struct super_block *sb, void *_data, int silent)
{
    printk(KERN_ALERT "DEBUG: ggfs_sb_fill");

    
	struct ggfs_sb_fill_data *data = _data;
	struct inode	*inode;
	struct ggfs_data	*ggfs = data->data;

	ggfs->sb              = sb;
	data->data            = NULL;
	sb->s_fs_info        = ggfs;
	sb->s_blocksize      = PAGE_SIZE;
	sb->s_blocksize_bits = PAGE_SHIFT;
	sb->s_magic          = GGFS_MAGIC;
	sb->s_op             = &ggfs_sb_operations;
	sb->s_time_gran      = 1;

	/* Root inode */
	data->perms.mode = data->root_mode;

	inode = ggfs_sb_make_inode(sb, NULL,
				  &simple_dir_operations,
				  &simple_dir_inode_operations,
				  &data->perms);

	sb->s_root = d_make_root(inode);

	if (unlikely(!sb->s_root))
		return -ENOMEM;

// 	/* EP0 file */
    if (unlikely(!ggfs_sb_create_file(sb, "value", ggfs,
 					 &value_file_operations)))
 		return -ENOMEM;

	return 0;
}

static int ggfs_fs_parse_opts(struct ggfs_sb_fill_data *data, char *opts)
{
        printk(KERN_ALERT "DEBUG: ggfs_fs_parse_opts");

        return 0;
}

static struct dentry *
ggfs_fs_mount(struct file_system_type *t, int flags,
	      const char *dev_name, void *opts)
{
    printk(KERN_ALERT "DEBUG: ggfs_fs_mount");

    
	struct ggfs_sb_fill_data data = {
		.perms = {
			.mode = S_IFREG | 0600,
			.uid = GLOBAL_ROOT_UID,
			.gid = GLOBAL_ROOT_GID,
		},
		.root_mode = S_IFDIR | 0500,
		.no_disconnect = false,
	};
	struct dentry *rv;
	int ret;
	struct ggfs_data	*ggfs;

	ret = ggfs_fs_parse_opts(&data, opts);
	if (unlikely(ret < 0))
		return ERR_PTR(ret);

	ggfs = ggfs_data_new();
	if (unlikely(!ggfs))
		return ERR_PTR(-ENOMEM);
	ggfs->file_perms = data.perms;
	ggfs->no_disconnect = data.no_disconnect;

	ggfs->dev_name = kstrdup(dev_name, GFP_KERNEL);
	if (unlikely(!ggfs->dev_name)) {
		ggfs_data_put(ggfs);
		return ERR_PTR(-ENOMEM);
	}

    ggfs->private_data = (void*)ggfs_init_private_data(device_gpios);
    data.data = ggfs;

	rv = mount_nodev(t, flags, &data,ggfs_sb_fill);
	if (IS_ERR(rv) && data.data) {
		ggfs_data_put(data.data);
	}
	return rv;
}

static void
ggfs_fs_kill_sb(struct super_block *sb)
{
    printk(KERN_ALERT "DEBUG: ggfs_fs_kill_sb");
	kill_litter_super(sb);
}

static struct file_system_type ggfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "ggfs",
	.mount		= ggfs_fs_mount,
	.kill_sb	= ggfs_fs_kill_sb,
};
MODULE_ALIAS_FS("ggfs");


/* Driver's main init/cleanup functions *************************************/

static int ggfs_init(void)
{
	int ret;

	ret = register_filesystem(&ggfs_fs_type);
	if (likely(!ret))
		pr_info("Gajos GPIO File System registered\n");
	else
		pr_err("Failed registering Gajos GPIO File System (%d)\n", ret);

	return ret;
}

static void ggfs_cleanup(void)
{

	pr_info("Unloading Gajos GPIO File System\n");
	unregister_filesystem(&ggfs_fs_type);
}

module_init(ggfs_init);
module_exit(ggfs_cleanup);
