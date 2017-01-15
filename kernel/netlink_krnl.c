#include <linux/module.h>
#include <net/sock.h> 
#include <linux/netlink.h>
#include <linux/skbuff.h> 

#define NETLINK_USER 31

struct sock *nl_sk = NULL;

static int netlink_send_multicast_msg(char* msg) 
{
	struct nlmsghdr *nlh;
    int pid;
    struct sk_buff *skb_out;
    int msg_size;
    int res;

    printk(KERN_INFO "[MYFW] Entering: %s\n", __FUNCTION__);

    msg_size = strlen(msg);

    skb_out = nlmsg_new(msg_size, 0);
    if (!skb_out) {
        printk(KERN_ERR "[MYFW] Failed to allocate new skb\n");
        return -1;
    }

    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb_out).dst_group = 1; /* not in mcast group */
    strncpy(nlmsg_data(nlh), msg, msg_size);

    res = nlmsg_multicast(nl_sk, skb_out, 0, 1, 0);
    if (res < 0)
        printk(KERN_ERR "[MYFW] Error while sending back to user\n");
    return res;
}

static void netlink_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    int pid;
    struct sk_buff *skb_out;
    int msg_size;
    char *msg = "[MYFW] Hello back from kernel!";
    int res;

    printk(KERN_INFO "[MYFW] Entering: %s\n", __FUNCTION__);

    //msg_size = strlen(msg);

    nlh = (struct nlmsghdr *)skb->data;
    pid = nlh->nlmsg_pid; /*pid of sending process */
    printk(KERN_INFO "Netlink received msg (pid %d) payload:%s\n", pid, (char *)nlmsg_data(nlh));

    /*
    skb_out = nlmsg_new(msg_size, 0);
    if (!skb_out) {
        printk(KERN_ERR "[MYFW] Failed to allocate new skb\n");
        return;
    }

    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb_out).dst_group = 1; 
    strncpy(nlmsg_data(nlh), msg, msg_size);

    res = nlmsg_multicast(nl_sk, skb_out, 0, 1, 0);
    if (res < 0)
        printk(KERN_INFO "[MYFW] Error while sending back to user\n");
    */
    netlink_send_multicast_msg(msg);
}

static void threex_krnl_init(void) 
{
	/* Linux kernel version 3.x init of Netlink socket */
    //nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, 0, netlink_recv_msg, NULL, THIS_MODULE);	
}

static int fourx_krnl_init(void) 
{
	/* Linux kernel version 4.x init of Netlink socket */
    struct netlink_kernel_cfg cfg = {
        .input = netlink_recv_msg
    };

    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
    if (!nl_sk) {
        printk(KERN_ALERT "[MYFW] Error creating socket.\n");
        return -10;
    }	

    return 0;
}

static void send_dummy_msg(void)
{
	char* dummy_msg = "dummy msg";
	netlink_send_multicast_msg(dummy_msg);
}

static int __init myfw_init(void)
{
	int res;
    printk("[MYFW] Entering: %s\n", __FUNCTION__);
    /* TODO: check linux kernel version and start netlink socket the proper way */
    /* Linux kernel version 4.x init of Netlink socket */
    struct netlink_kernel_cfg cfg = {
        .input = netlink_recv_msg
    };

    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
    if (!nl_sk) {
        printk(KERN_ALERT "[MYFW] Error creating socket.\n");
        return -10;
    }	

    /* TODO: hook netfilter for network traffic filtering and send msg to userland broker service */

    return 0;
}

static void __exit myfw_exit(void)
{

    printk(KERN_INFO "[MYFW] exiting module\n");
    netlink_kernel_release(nl_sk);
}

module_init(myfw_init); module_exit(myfw_exit);

MODULE_LICENSE("GPL");