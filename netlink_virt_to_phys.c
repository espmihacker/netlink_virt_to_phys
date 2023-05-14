#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <net/sock.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jayne");
MODULE_DESCRIPTION("A simple example of a Netlink kernel module");
MODULE_VERSION("0.1");

#define NETLINK_USER 31

struct sock *nl_sk = NULL;
struct netlink_kernel_cfg cfg;

static inline unsigned long pte_to_phys(unsigned long virt_addr, unsigned long pte_value) {
    return (virt_addr & ~PAGE_MASK) | (pte_value & PAGE_MASK);
}

static inline struct mm_struct *get_mm_by_pid(pid_t pid)
{
	struct task_struct *task;

	task = pid_task(find_vpid(pid), PIDTYPE_PID);
	if (!task)
		return NULL;
	
	return get_task_mm(task);
}


static size_t get_addr_pte(struct mm_struct *mm, size_t virt_addr, pte_t **pte)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	
	pgd = pgd_offset(mm, virt_addr);
	if (pgd_none(*pgd))
		return 0;
	
	p4d = p4d_offset(pgd, virt_addr);
	if (p4d_none(*p4d))
		return 0;
		
	pud = pud_offset(p4d, virt_addr);
	if (pud_none(*pud))
		return 0;
		
	pmd = pmd_offset(pud, virt_addr);
	if (pmd_none(*pmd))
		return 0;
	
	*pte = pte_offset_kernel(pmd, virt_addr);
	if (pte_none(**pte))
		return 0;
	
	return pte_val(**pte);
}

static void nl_recv_msg(struct sk_buff *skb) {
    struct nlmsghdr *nlh;
    int pid;
    int send_pid;
    struct sk_buff *skb_out;
    int msg_size;
    char *msg;
    int res;
    unsigned long virt_addr;
    unsigned long phys_addr;
    size_t page_addr;
    void *kernel_addr;
    struct mm_struct *mm;
    pte_t *pte = NULL;
    int data;

    char *input;
    char *virt_addr_str;
    char *offset_str;
    char *pid_str;
    unsigned long offset;

    printk(KERN_INFO "Entering: %s\n", __FUNCTION__);

    nlh = (struct nlmsghdr *)skb->data;
    //printk(KERN_INFO "Netlink received msg payload: %s\n", (char *)nlmsg_data(nlh));

    send_pid = nlh->nlmsg_pid; // pid of sending process


    // Parse virtual address and offset
    

    input = (char *)nlmsg_data(nlh);
    virt_addr_str = strsep(&input, " ");
    offset_str = strsep(&input, " ");
    pid_str = strsep(&input, " ");
    virt_addr = simple_strtoul(virt_addr_str, NULL, 16);
    offset = simple_strtoul(offset_str, NULL, 10);
    pid = simple_strtoul(pid_str, NULL, 10);
    phys_addr = 0;

    //printk(KERN_ERR "v2p: send pid: %d,pid: %d\n",send_pid,pid);
    mm = get_mm_by_pid(pid);

    page_addr = get_addr_pte(mm, virt_addr, &pte);

    //printk(KERN_ERR "v2p: page_addr,%lx\n",page_addr);

    if (mm && pte && pte_present(*pte) && pfn_valid(pte_pfn(*pte))) {
        //printk(KERN_ERR "v2p: 1,%lx\n",virt_addr);
        phys_addr = pte_to_phys(virt_addr, pte_val(*pte)) & 0x7fffffffffffffULL;
        //printk(KERN_ERR "v2p: 2,%lx\n",phys_addr);
        kernel_addr = __va(phys_addr);
        data = *(int *)kernel_addr;
        //printk(KERN_ERR "v2p: 3,%d\n",data);
    }else{
        printk(KERN_ERR "v2p: Failed to mm or pte\n");
    }

    msg_size = sizeof(data);

    skb_out = nlmsg_new(msg_size, 0);
    if (!skb_out) {
        printk(KERN_ERR "Failed to allocate new skb\n");
        return;
    }

    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    if (!nlh) {
        printk(KERN_ERR "Failed to create netlink message header\n");
        nlmsg_free(skb_out);
        return;
    }

    memcpy(nlmsg_data(nlh), &data, msg_size);

    res = nlmsg_unicast(nl_sk, skb_out, send_pid);
    if (res < 0) {
        printk(KERN_INFO "Error while sending back to user\n");
    }

    kfree(msg);
}



static int __init netlink_virt_to_phys_init(void) {
    printk(KERN_INFO "Loading netlink_virt_to_phys module...\n");

    cfg.input = nl_recv_msg;

    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
    if (!nl_sk) {
        printk(KERN_ALERT "Error creating socket.\n");
        return -10;
    }

    return 0;
}

static void __exit netlink_virt_to_phys_exit(void) {
    printk(KERN_INFO "Unloading netlink_virt_to_phys module...\n");

    netlink_kernel_release(nl_sk);
}

module_init(netlink_virt_to_phys_init);
module_exit(netlink_virt_to_phys_exit);
