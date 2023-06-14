#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/inet.h>

// Thêm dòng này để khai báo biến module parameter
static char *director_ip = "10.0.2.10";
module_param(director_ip, charp, 0);
MODULE_PARM_DESC(director_ip, "IP address of the director's PC");

static struct nf_hook_ops nfho;

unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

// Hàm khởi tạo module
static int __init init_firewall_module(void) {
    nfho.hook = hook_func;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nfho);

    return 0;
}

// Hàm dọn dẹp module
static void __exit cleanup_firewall_module(void) {
    nf_unregister_net_hook(&init_net, &nfho);
}

module_init(init_firewall_module);
module_exit(cleanup_firewall_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Company IT");
MODULE_DESCRIPTION("A simple firewall module for the company server");

// Hàm hook_func sẽ được gọi khi có gói tin đi qua
unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct in_addr client_ip;
    uint32_t client_ip_int;

    iph = ip_hdr(skb);
    tcph = tcp_hdr(skb);

    // Chuyển đổi IP PC của giám đốc từ chuỗi sang dạng số
    in4_pton(director_ip, -1, (u8 *)&client_ip_int, -1, NULL);
    client_ip.s_addr = client_ip_int;
    // Kiểm tra nếu gói tin đến từ localhost (127.0.0.1) hoặc một địa chỉ IP bất kỳ (0.0.0.0)
    if (iph->saddr == htonl(INADDR_LOOPBACK) || iph->saddr == htonl(INADDR_ANY)) {
        printk(KERN_INFO "company_firewall: packet from %pI4 accepted\n", &iph->saddr);
        return NF_ACCEPT;
    }
    // Kiểm tra nếu gói tin đến từ PC của giám đốc
    if (iph->saddr == client_ip.s_addr) {
        printk(KERN_INFO "company_firewall: packet from director's IP (%s) accepted\n", director_ip);
        return NF_ACCEPT;
    }

    // Chặn tất cả các gói tin khác
    printk(KERN_INFO "company_firewall: packet from other IP (%pI4) dropped\n", &iph->saddr);
    return NF_DROP;
}

