#include <linux/init.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/gpio.h>
#include <linux/list.h>
#include <linux/interrupt.h>
#include <linux/time.h>
#include <linux/string.h>
#include <linux/security.h>
#include <linux/spinlock.h>

MODULE_AUTHOR("Pawel Gajewski, SciTeeX Company");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Simple File System to gathering information from Onion IoT pin (or another Linux devices)");
MODULE_VERSION("0.3");
MODULE_INFO(intree, "Y");

#define GGFS_MAGIC	0xa647361

////////////////////////////////////Data types//////////////////////////////////////////////
typedef enum {
    low = 0, high = 1
}state;
typedef enum {
    input, output
}direction;

// Time 
struct cycle_time
{
    time_t time;
    struct list_head list;
};

struct ggfs_gpio
{
    unsigned int gpio_num;
	unsigned int confirm_gpio;
    unsigned int irq_number;
    time_t last_event_time;
	state state;
	direction direction;
	struct mutex mut;
    time_t total_time;
    struct cycle_time time_list;
    spinlock_t lock;
    struct list_head list;
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
    gpio->total_time += process_time;
    //Add a list node.
    list_add_tail(&new_time->list, &gpio->time_list.list);

    //Add new last time event.
    gpio->last_event_time = end_time;
    
    //Print times
    printk(KERN_INFO "Gajos GPIO File System: Last operation time: %u msec. Total time: %u msec", process_time, gpio->total_time);
    
    return (irq_handler_t) IRQ_HANDLED;      // Announce that the IRQ has been handled correctly

}

static irq_handler_t ggfs_gpio_irq_handler(unsigned int irq, void *dev_id, struct pt_regs *regs){
    
    //Cast dev pointer.
    struct ggfs_gpio* this_gpio = (struct ggfs_gpio*)dev_id;
    unsigned long flags;
     //Set confirm gpio value.
    spin_lock_irqsave(&this_gpio->lock, flags);
    int gpio_value = gpio_get_value(this_gpio->gpio_num);
    gpio_set_value(this_gpio->confirm_gpio, gpio_value);

    this_gpio->state = gpio_value;
    //Get IRQ flag
    printk(KERN_INFO "Gajos GPIO File System: Interrupt on %d! Value: %d", this_gpio->gpio_num, gpio_value);
    irq_handler_t result;
    
    switch(gpio_value)
    {
        case 0: result = ggfs_gpio_falling_handler(this_gpio); break;
        case 1: result = ggfs_gpio_rising_handler(this_gpio); break;
    }
    spin_unlock_irqrestore(&this_gpio->lock, flags);

    return result;   
}

static int set_gpio_direction(struct ggfs_gpio* gpio, direction new_direction)
{
    int result;
    unsigned long flags;
    spin_lock_irqsave(&gpio->lock, flags);

    printk(KERN_ALERT "DEBUG: set_gpio_direction");
    printk(KERN_ALERT "GGFS: changing state on gpio %d", gpio->gpio_num);
    
    if(new_direction == input)
    {
        char gpio_handler_name[15];
        sprintf(gpio_handler_name, "gpio%d_handler", gpio->gpio_num);
        
        gpio_direction_input(gpio->gpio_num);
        
        //Set handlers.
        result = request_irq(gpio->irq_number,                                // The interrupt number requested
                    (irq_handler_t) ggfs_gpio_irq_handler,              // The pointer to the handler function below
                    IRQF_TRIGGER_RISING | IRQF_TRIGGER_FALLING,         // Interrupt on rising edge (input active)
                    gpio_handler_name,                                  // Used in /proc/interrupts to identify the owner
                    gpio);
        
        printk(KERN_ALERT "GGFS: set_gpio_direction");
        
        //Check adding handler error.
        if(result)
        {
        spin_unlock_irqrestore(&gpio->lock, flags);
            return result;
        }
    }
    else
    {
        gpio_direction_output(gpio->gpio_num,0);
        spin_unlock_irqrestore(&gpio->lock,flags);
    }
    return 0;

}

static void ggfs_gpio_set_output(struct ggfs_gpio * gpio, state state)
{
    unsigned long flags;
    spin_lock_irqsave(&gpio->lock, flags);
    gpio->state = state;
    gpio_set_value(gpio->gpio_num, state == high);
    gpio_set_value(gpio->confirm_gpio, state);
    spin_unlock_irqrestore(&gpio->lock, flags);

}

static struct ggfs_gpio* init_gpio(unsigned int gpio_number, unsigned int confirm_gpio, unsigned int max_gpio, struct ggfs_gpio* gpio_list)
{
    printk(KERN_ALERT "GGFS: init_gpios");
    struct ggfs_gpio* temp, *new_gpio;
    list_for_each_entry(temp, &gpio_list->list, list)
    {
         if(temp->gpio_num == gpio_number || temp->confirm_gpio == gpio_number
             || temp->gpio_num == confirm_gpio || temp->confirm_gpio == confirm_gpio)
         return NULL;
    }

    if(gpio_number > max_gpio || confirm_gpio > max_gpio)
        return NULL;
    
    //Check gpio.
    if(unlikely(gpio_request(gpio_number, "ggfs")))
    {
        return NULL;
    }
    
    if(unlikely(gpio_request(confirm_gpio, "ggfs")))
    {
        gpio_free(gpio_number);
        return NULL;
    }

    //Check handlers.
    new_gpio = kmalloc(sizeof(*new_gpio), GFP_KERNEL);
    
    new_gpio->gpio_num = gpio_number;
    new_gpio->confirm_gpio = confirm_gpio;
    
    //Get irq number.
    new_gpio->irq_number = gpio_to_irq(gpio_number);
    
    //Set direction. Init new gpio as input.
    direction direction = input;

    set_gpio_direction(new_gpio, direction);
    
    //Set confirm GPIO.
    gpio_direction_output(new_gpio->confirm_gpio, gpio_get_value(new_gpio->gpio_num));
    
    //Init semathore.
    mutex_init(&new_gpio->mut);
    spin_lock_init(&new_gpio->lock);
    
    //Init time list.
    new_gpio->total_time = 0;
    INIT_LIST_HEAD(&new_gpio->time_list.list);
    
    //Init list head.
    INIT_LIST_HEAD(&new_gpio->list);
    
    list_add(&new_gpio->list, &gpio_list->list);

    printk(KERN_INFO "DEBUG: %u %u", new_gpio->gpio_num, new_gpio->confirm_gpio);

    
    return new_gpio;
}

static void release_gpio(struct ggfs_gpio* gpio)
{
    
    //Release GPIOs.
    gpio_free(gpio->gpio_num);
    free_irq(gpio->irq_number, gpio);
    gpio_free(gpio->confirm_gpio);

    //Init list head.
    list_del(&gpio->time_list.list);
    
    kfree(gpio);
    
}



///////////////////////////////File operations funcions////////////////////////
static ssize_t value_file_write(struct file *file, const char __user *buf,
			     size_t len, loff_t *ptr)
{
    char buffer[1];
    
    printk(KERN_ALERT "Buffer size: %u", len);
    struct ggfs_gpio *gpio = file->private_data;
    if(gpio->direction == input)
    {
        return -EINVAL;
    }
    if(len != 1)
    {
        return -EINVAL;
    }
    printk(KERN_ALERT "Before copy from user");
    if(unlikely(copy_from_user (buffer, buf, 1)))
    {
        return -EFAULT;
    }
    printk(KERN_ALERT "After copy from user");
    state new_state;
    if(buffer[0] == '0')
        new_state = low;
    else if(buffer[0] == '1')
        new_state = high;
    else
        return -EINVAL;
    ggfs_gpio_set_output(gpio, new_state);
    return 0;
}

static ssize_t value_file_read(struct file *file, char __user *buf,
			    size_t len, loff_t *ptr)
{
    unsigned long flags;
    int ret;
    char buffer[1];
    struct ggfs_gpio *gpio = file->private_data;  //EOF *ptr > 1
//     if(*ptr > 1 && len == 0)
//     {
      printk(KERN_INFO "GPIO %u-%u: Device is using by another process", gpio->gpio_num, gpio->confirm_gpio);

//         ret = 0;
//     }
//     else
//     {
        
        spin_lock_irqsave(&gpio->lock,flags);
        sprintf(buffer, "%i", gpio->state);
        spin_unlock_irqrestore(&gpio->lock,flags);
        ret = copy_to_user(buf, buffer, 1);
//     }
	return 0;
}


static int value_file_open(struct inode *inode, struct file *file)
{
	struct ggfs_gpio *gpio = (struct ggfs_gpio*)inode->i_private;

    //Try to allocate mutex.
    if(!mutex_trylock(&gpio->mut)){

      printk(KERN_INFO "GPIO %u-%u: Device is using by another process", gpio->gpio_num, gpio->confirm_gpio);

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
    char buffer[6];
    printk(KERN_INFO "%s", buf);
    struct ggfs_gpio *gpio = file->private_data;
    if(copy_from_user (buffer, buf, 6))
    {
        printk(KERN_INFO "Złe kopiowanie");
        return -EFAULT;
    }
    if(!strcmp(buffer, "input"))
    {
        spin_lock(&gpio->lock);
        set_gpio_direction(gpio, input);
        return 0;
    }
    if(!strcmp(buffer, "output"))
    {
        set_gpio_direction(gpio, output);
        return 0;
    }
    return -EINVAL;
}

static ssize_t direction_file_read(struct file *file, char __user *buf,
			    size_t len, loff_t *ptr)
{
    struct ggfs_gpio *gpio = file->private_data;
    if(gpio->direction == output)
    {
        if(!copy_to_user(buf, "output", 6))
            return 6;
        else
            return -EFAULT;
    }
    
    if(gpio->direction == input)
    {
        if(!copy_to_user(buf, "input", 5))
            return 5;
        else
            return -EFAULT;
    }
	return -EFAULT;
}


static int direction_file_open(struct inode *inode, struct file *file)
{
	struct ggfs_gpio *gpio = (struct ggfs_gpio*)inode->i_private;

    //Try to allocate mutex.
    if(!mutex_trylock(&gpio->mut)){

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
    char buffer[6];
    printk(KERN_INFO "%s", buf);
    struct ggfs_gpio *gpio = file->private_data;
    if(copy_from_user (buffer, buf, 6))
    
    if(!strcmp(buf,"reset"))
    {
        gpio->total_time = 0;
    }
    
    mutex_unlock(&gpio->mut);

    return 0;
}

static ssize_t total_time_file_read(struct file *file, char __user *buf,
			    size_t len, loff_t *ptr)
{
    struct ggfs_gpio *gpio = (struct ggfs_gpio*)file->private_data;
    char * buffer;
    int ret = copy_to_user(buf, buffer, sprintf(buffer, "%u", gpio->total_time));
    return ret;
    
}


static int total_time_file_open(struct inode *inode, struct file *file)
{
	struct ggfs_gpio *gpio = (struct ggfs_gpio*)inode->i_private;

    //Try to allocate mutex.
    if(!mutex_trylock(&gpio->mut)){

      printk(KERN_INFO "GPIO %u-%u: Device is using by another process", gpio->gpio_num, gpio->confirm_gpio);

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

      printk(KERN_INFO "GPIO %u-%u: Device is using by another process", gpio->gpio_num, gpio->confirm_gpio);

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

      printk(KERN_INFO "GPIO %u-%u: Device is using by another process", gpio->gpio_num, gpio->confirm_gpio);

      return -EBUSY;
   }
   	file->private_data = gpio;

    return 0;
}

static int info_file_release(struct inode *inode, struct file *file)
{

	struct ggfs_gpio *gpio = file->private_data;

    mutex_unlock(&gpio->mut);
    
    return 0;
    
}

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
	struct ggfs_gpio gpios_list;
    struct mutex list_mut;
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
	 * mounted.f
	 */
	struct super_block		*sb;
    
    /*File permissions */
    struct ggfs_file_perms file_perms;
    
    bool no_disconnect;
};

////////////////////////////////////Module parameters///////////////////////////////////////

// Number of GPIo in device..
static unsigned int device_gpios = 40;

MODULE_PARM_DESC(device_gpios, "Number of GPIOs in device");
module_param(device_gpios, uint, S_IRUGO);


////////////////////////////////////////////////////////////////////////////////////////////
//File inodes.
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
static struct dentry *ggfs_create_file(struct super_block *sb,
					const char *name, struct dentry * parent, void *data,
					const struct file_operations *fops)
{
    printk(KERN_ALERT "DEBUG: ggfs_sb_create_file");

    //Create using GPIO.
    struct ggfs_data	*ggfs = sb->s_fs_info;
	struct inode	*inode;
    struct dentry  *dentry;


	dentry = d_alloc_name(parent, name);
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

/* Create directory as GPIO */
static int ggfs_create_directory(struct super_block *sb,
                     struct dentry * dentry, void *data)
{
    printk(KERN_ALERT "DEBUG: ggfs_sb_create_directory");

    //Create using GPIO.
    struct ggfs_data	*ggfs = sb->s_fs_info;
	struct inode	*inode;

	if (unlikely(!dentry))
		return -1;
    
    
	inode = ggfs_sb_make_inode(sb, data, &simple_dir_operations, &simple_dir_inode_operations, &ggfs->file_perms);
	if (unlikely(!inode)) {
		dput(dentry);
		return -1;
	}
	
	//Change to directory node.
	inode->i_mode = S_IFDIR | S_IRUGO | S_IXUGO;
    printk(KERN_INFO "DEBUG: Inode created!");

    d_instantiate(dentry, inode);
    
    printk(KERN_INFO "DEBUG: Inode added!");

	return 0;
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
    struct ggfs_gpio * gpio, *temp;
    mutex_lock(&priv_data->list_mut);

    list_for_each_entry_safe(gpio, temp, &priv_data->gpios_list.list, list)
    {
        release_gpio(gpio);
    }
    mutex_unlock(&priv_data->list_mut);
    kfree(priv_data);

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
    struct ggfs_sb_priv_data * data;
    data = kmalloc(sizeof(*data), GFP_KERNEL);
    INIT_LIST_HEAD(&data->gpios_list.list);
    data->gpios_number = gpios_number;
    data->used_gpios = 0;

    //Init mutex.
    mutex_init(&data->list_mut);
    return data;
}

//////////////////////////////////////Directory operations////////////////////
static int ggfs_mkdir(struct inode * inode, struct dentry * dentry, umode_t umode)
{
    int ret;
    printk(KERN_ALERT "DEBUG: ggfs_mkdir");
    char* name =kstrdup(dentry->d_name.name, GFP_KERNEL);
    printk(KERN_ALERT "%s", name);
    unsigned int main_gpio;
    unsigned int confirm_gpio;
    struct ggfs_gpio * dir_gpio;
    
    //Check if mkdir is called in root directory.
    if(dentry->d_parent != inode->i_sb->s_root)
        return -EPERM;
    
    const char* main_gpio_s = strsep(&name, "-");
    const char* confirm_gpio_s = kstrdup(name, GFP_KERNEL);

//     if(dentry->d_parent != NULL && dentry->d_parent->d_inode == inode)
//     {
//         printk(KERN_ALERT "DEBUG: Inode rodzica!");
//     }
    
    if(kstrtouint(main_gpio_s, 0, &main_gpio) ||kstrtouint(confirm_gpio_s, 0, &confirm_gpio))
    {
        return -EINVAL;
    }

    //Get data from super block.
    struct ggfs_data	*ggfs = (struct ggfs_data*)inode->i_sb->s_fs_info;
    
    struct ggfs_sb_priv_data* data = (struct ggfs_sb_priv_data*)ggfs->private_data;
    
    if(mutex_lock_interruptible(&data->list_mut))
    {
        return -EINTR;
    }
    dir_gpio = init_gpio(main_gpio, confirm_gpio, data->gpios_number, &data->gpios_list);
    printk(KERN_INFO "DEBUG: GPIO created!");
    
    if(dir_gpio == NULL)
        return -EINVAL;

    ++data->used_gpios;
    mutex_unlock(&data->list_mut);

    printk(KERN_INFO "DEBUG: GPIO added!");
    ret = ggfs_create_directory(inode->i_sb, dentry, dir_gpio); 
    if(ret)
    {
        release_gpio(dir_gpio);
        return ret;
    }
    printk(KERN_INFO "DEBUG: Directory created!");
    
     //Add files to directory node
    ggfs_create_file(inode->i_sb,"value", dentry, dir_gpio, &value_file_operations);
    ggfs_create_file(inode->i_sb,"direction", dentry, dir_gpio, &direction_file_operations);
    ggfs_create_file(inode->i_sb,"total_time", dentry, dir_gpio, &total_time_file_operations);
    ggfs_create_file(inode->i_sb,"time_list",dentry, dir_gpio, &time_list_file_operations);

    printk(KERN_ALERT "DEBUG: Directory filled!");
    
    return 0;
}

static int ggfs_rmdir (struct inode * inode,struct dentry * dentry)
{
    //Get data from super block.
    struct ggfs_data	*ggfs = (struct ggfs_data*)inode->i_sb->s_fs_info;
    
    struct ggfs_sb_priv_data* data = (struct ggfs_sb_priv_data*)ggfs->private_data;
    
    struct ggfs_gpio * gpio = inode->i_private;
    
    list_del(&gpio->list);
    release_gpio(gpio);
    --data->used_gpios;
    
    //Relesae dentry.
    dput(dentry);
    
    return 0;
}

static const struct inode_operations ggfs_root_inode_operations = {
    .lookup = simple_lookup,
    .mkdir = ggfs_mkdir,
    .rmdir = ggfs_rmdir,
};

static int ggfs_sb_fill(struct super_block *sb, void *_data, int silent)
{
    printk(KERN_ALERT "DEBUG: ggfs_sb_fill");
// 
    
	struct ggfs_sb_fill_data *data = _data;
	struct inode	*inode;
	struct ggfs_data	*ggfs = data->data;

	ggfs->sb             = sb;
	data->data           = NULL;
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
				  &ggfs_root_inode_operations,
				  &data->perms);

	sb->s_root = d_make_root(inode);

	if (unlikely(!sb->s_root))
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
			.mode = S_IFREG | 0766,
			.uid = GLOBAL_ROOT_UID,
			.gid = GLOBAL_ROOT_GID,
		},
		.root_mode = S_IFDIR | 0755,
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
    struct ggfs_data	*ggfs = (struct ggfs_data*)sb->s_fs_info;
    printk(KERN_ALERT "DEBUG: ggfs_fs_kill_sb");
    ggfs_data_put(ggfs);
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
