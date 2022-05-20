#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/cdev.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/delay.h>

#include "peach.h"
#include "guest.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ScratchLab");

static dev_t peach_dev; // peach设备结构体
static struct cdev peach_cdev; // 字符设备

static long peach_ioctl(struct file *file,
			unsigned int cmd,
			unsigned long data);
static struct file_operations peach_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = peach_ioctl, // 指定了ioctl接口的handle函数（全部由ioctl完成）
};

struct vmcs_hdr {
	u32 revision_id:31;
	u32 shadow:1;
};

#define VMX_SIZE_MAX 4096
struct vmcs {
	struct vmcs_hdr hdr;
	u32 abort;
	char data[VMX_SIZE_MAX - 8];
};

static struct vmcs *vmxon;
static struct vmcs *vmcs;

static u8 *stack;

#define GUEST_MEMORY_SIZE (0x1000 * 16) // 最大guest内存
static u8 *guest_memory; // guest内存指针

#define EPT_MEMORY_SIZE (0x1000 * 4)
static unsigned char *ept_memory; // 扩展页表内存指针

static void init_ept(u64 *ept_pointer, u64 guest_memory_pa);
static void init_ept_pointer(u64 *p, u64 pa);
static void init_pml4e(u64 *entry, u64 pa);
static void init_pdpte(u64 *entry, u64 pa);
static void init_pde(u64 *entry, u64 pa);
static void init_pte(u64 *entry, u64 pa);

/* 
（重要！）
VM在运行时可以因为某些中断或者IO从VM中退出进入VMM预设的处理逻辑，此时的行为可由用户自定义！
具体实现在vmexit_handler.S中
其主要实现的功能就是保存虚拟机运行时的上下文，然后调用handle_vmexit函数
调用结束后恢复上下文，虚拟机执行流从中断处继续
*/
void _vmexit_handler(void); 

// 客户机的寄存器结构体
struct guest_regs {
	u64 rax;
	u64 rcx;
	u64 rdx;
	u64 rbx;
	u64 rbp;
	u64 rsp;
	u64 rsi;
	u64 rdi;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
};
static void dump_guest_regs(struct guest_regs *regs);

static u64 shutdown_rsp;
static u64 shutdown_rbp;

// 初始化peach虚拟机的内核模块
static int peach_init(void)
{
	printk("PEACH INIT\n");

	peach_dev = MKDEV(PEACH_MAJOR, PEACH_MINOR); // 获取设备在设备表中的位置（主设备号，次设备号）
	if (0 < register_chrdev_region(peach_dev, PEACH_COUNT, "peach")) { // 为提前知道设备的主次设备号的设备分配设备编号
		printk("register_chrdev_region error\n");

		goto err0;
	}

	cdev_init(&peach_cdev, &peach_fops); // 初始化字符设备，第二个参数传入字符设备的操作方法接口
	peach_cdev.owner = THIS_MODULE;

	if (0 < cdev_add(&peach_cdev, peach_dev, 1)) { // 向操作系统添加peach字符设备
		printk("cdev_add error\n");

		goto err1;
	}

	return 0;

err1:
	unregister_chrdev_region(peach_dev, 1);

err0:

	return -1;
}

static void peach_exit(void)
{
	printk("PEACH EXIT\n");

	cdev_del(&peach_cdev); // 从操作系统中删去peach字符设备
	unregister_chrdev_region(peach_dev, 1); // 取消注册

	return;
}

// （核心）peach通过ioctl接收控制指令的主要接口
static long peach_ioctl(struct file *file,
			unsigned int cmd,
			unsigned long arg)
{
	int i;

	u8 ret1;

	u32 edx, eax, ecx;
	u64 rdx;

	u64 vmcs_pa;
	u64 vmxon_pa;

	u8 xdtr[10];
	u64 vmcs_field;
	u64 vmcs_field_value;

	u64 host_tr_selector;
	u64 host_gdt_base;
	u64 host_tr_desc;

	u64 ept_pointer;
	u64 guest_memory_pa;

	switch (cmd) {
	case PEACH_PROBE:
		printk("PEACH PROBE\n");
		/* 
		 这些操作的主要目的是把物理机的msr寄存器
		 信息通过rdmsr读到虚拟机的寄存器中，其保
		 存的大多是一些平台相关的常量，这么做的目
		 的可能是为了支持CPUID指令！
		 */
		/* 
		 (MSR) 的模型特定寄存器：
		 方法ReadMsr和WriteMsr读取和写入MSRs，这
		 是为特定CPU型号启用和禁用功能并支持调
		 试的控制寄存器
		 */
		ecx = 0x480;
		asm volatile (
			"rdmsr\n\t"
			: "=a" (eax), "=d" (edx)
			: "c" (ecx)
		);
		printk("IA32_VMX_BASIC = 0x%08x%08x\n", edx, eax);

		ecx = 0x486;
		asm volatile (
			"rdmsr\n\t"
			: "=a" (eax), "=d" (edx)
			: "c" (ecx)
		);
		printk("IA32_VMX_CR0_FIXED0 = 0x%08x%08x\n", edx, eax);

		ecx = 0x487;
		asm volatile (
			"rdmsr\n\t"
			: "=a" (eax), "=d" (edx)
			: "c" (ecx)
		);
		printk("IA32_VMX_CR0_FIXED1 = 0x%08x%08x\n", edx, eax);

		ecx = 0x488; 
		asm volatile (
			"rdmsr\n\t"
			: "=a" (eax), "=d" (edx)
			: "c" (ecx)
		);
		printk("IA32_VMX_CR4_FIXED0 = 0x%08x%08x\n", edx, eax);

		ecx = 0x489;
		asm volatile (
			"rdmsr\n\t"
			: "=a" (eax), "=d" (edx)
			: "c" (ecx)
		);
		printk("IA32_VMX_CR4_FIXED1 = 0x%08x%08x\n", edx, eax);

		ecx = 0x48D; 
		asm volatile (
			"rdmsr\n\t"
			: "=a" (eax), "=d" (edx)
			: "c" (ecx)
		);
		printk("IA32_VMX_TRUE_PINBASED_CTLS = 0x%08x%08x\n", edx, eax);

		ecx = 0x48E; 
		asm volatile (
			"rdmsr\n\t"
			: "=a" (eax), "=d" (edx)
			: "c" (ecx)
		);
		printk("IA32_VMX_TRUE_PROCBASED_CTLS = 0x%08x%08x\n", edx, eax);

		ecx = 0x48B; 
		asm volatile (
			"rdmsr\n\t"
			: "=a" (eax), "=d" (edx)
			: "c" (ecx)
		);
		printk("IA32_VMX_PROCBASED_CTLS2 = 0x%08x%08x\n", edx, eax);

		ecx = 0x48F; 
		asm volatile (
			"rdmsr\n\t"
			: "=a" (eax), "=d" (edx)
			: "c" (ecx)
		);
		printk("IA32_VMX_TRUE_EXIT_CTLS = 0x%08x%08x\n", edx, eax);

		ecx = 0x490; 
		asm volatile (
			"rdmsr\n\t"
			: "=a" (eax), "=d" (edx)
			: "c" (ecx)
		);
		printk("IA32_VMX_TRUE_ENTRY_CTLS = 0x%08x%08x\n", edx, eax);

		ecx = 0x48C; 
		asm volatile (
			"rdmsr\n\t"
			: "=a" (eax), "=d" (edx)
			: "c" (ecx)
		);

		ecx = 0x48C; 
		asm volatile (
			"rdmsr\n\t"
			: "=a" (eax), "=d" (edx)
			: "c" (ecx)
		);
		printk("IA32_VMX_EPT_VPID_CAP = 0x%08x%08x\n", edx, eax);

		break;

	case PEACH_RUN:
		printk("PEACH RUN\n");
		/* 
		 虚拟机启动命令
		 */
		/* 通过kmalloc分配guest的物理内存 */
		guest_memory = (u8 *) kmalloc(GUEST_MEMORY_SIZE,
							GFP_KERNEL);
		/*（重点）
		之所以要计算pa是因为EPT目的是帮助guest物理内存直通host物理内存，
		所以要保证写进页表中表项的每个值都是host物理内存的地址；
		但是在程序中的写操作发生时依然用到的是内核虚拟地址va的指针值
		*/
		guest_memory_pa = __pa(guest_memory);

		/* 这里往guest的物理内存起始位置拷贝guest镜像（迷你镜像） */
		for (i = 0; i < guest_bin_len; i++) {
			guest_memory[i] = guest_bin[i];
		}
		/* 初始化EPT各级页表，最后的页索引会索引到刚刚创建的guest_memory_pa各个页上 */
		/* 注意EPT页表和guest内存是可以分别由两个kmalloc创建的 */
		init_ept(&ept_pointer, guest_memory_pa);

		/* 初始化vmxon对象 */
		/* （重点）
		对于Intel x86处理器，在打开VMX（Virtual Machine Extension），即执行VMXON
		指令的时候需要提供一个4KB对齐的内存区间，称作VMXON region，该区域的物理地
		址作为VMXON指令的操作数。
		该内存区间用于支持逻辑CPU的VMX功能，该区域在VMXON和VMXOFF之间一直都会被VMX硬件所使用。
		每个逻辑CPU都应该分配一个VMXON Region.
		*/
		vmxon = (struct vmcs *) kmalloc(4096, GFP_KERNEL);
		memset(vmxon, 0, 4096);
		vmxon->hdr.revision_id = 0x00000001;
		vmxon->hdr.shadow = 0x00000000;
		vmxon_pa = __pa(vmxon);
		/* 初始化vmcs对象 */
		/* VMXON Region和VMCS Region是不一样的两个内存区域，VMXON是针对逻辑CPU的，
		每个逻辑CPU都会有一份，并且在整个VMX功能使用期间硬件都会使用；而VMCS Region
		则是针对vCPU的，每个vCPU都会有一份VMCS Region，用于辅助硬件对vCPU的模拟。
		也就是说之前提前绑定了一个物理CPU，所以需要一个VMXON Region，而往下的客户机
		也只使用一个vCPU，所以也只需要一个VMCS Region
		*/
		vmcs = (struct vmcs *) kmalloc(4096, GFP_KERNEL);
		memset(vmcs, 0, 4096);
		vmcs->hdr.revision_id = 0x00000001;
		vmcs->hdr.shadow = 0x00000000;
		vmcs_pa = __pa(vmcs);

		/* 
		从cr4中取出第13位放入CF中并将该位设为1，再更新cr4
		（重要）
		这一步的目的是打开cr4寄存器中的虚拟化开关！
		 */
		asm volatile (
			"movq %cr4, %rax\n\t"
			"bts $13, %rax\n\t"
			"movq %rax, %cr4"
		);

		/* 
		（重要）vmxon指令通过传入VMXON Region的“物理地址”作为操作数，表示进入VMX操作模式
		EFLAGS.CF 可判断执行是否成功
		setna使得D = CF | ZF，表示低于或等于(无符号<=)
		 */
		asm volatile (
			"vmxon %[pa]\n\t"
			"setna %[ret]"
			: [ret] "=rm" (ret1)
			: [pa] "m" (vmxon_pa)
			: "cc", "memory"
		);
		/*
		（重要） 
		在clobbered list中加入cc和memory会告诉编译器
		内联汇编会修改cc（状态寄存器标志位）和memory（内存）中的值
		于是编译器不会再假设这段内联汇编后对应的值依然是合法的
		（重要）
		理论上来说只要在内联汇编中破坏了某些额外值，都需要标注出来！
		 */
		printk("vmxon = %d\n", ret1);

		/* vmclear指令用于清除当前VMCS结构体，传入vmcs物理地址作为操作数字 */
		asm volatile (
			"vmclear %[pa]\n\t"
			"setna %[ret]"
			: [ret] "=rm" (ret1)
			: [pa] "m" (vmcs_pa)
			: "cc", "memory"
		);
		printk("vmclear = %d\n", ret1);

		/* 
		（重要）
		加载一个VMCS结构体指针作为当前操作对象（pointer load）！
		被加载到逻辑CPU上后处理器并没法通过普通的内存访问指令去访问VMCS，
		如果那样做的话，会引起“处理器报错”，唯一可用的方法就是通过VMREAD和VMWRITE指令去访问。
		可以理解为逻辑CPU为当前正在使用的VMCS对象添加了一层“访问保护”
		 */
		asm volatile (
			"vmptrld %[pa]\n\t"
			"setna %[ret]"
			: [ret] "=rm" (ret1)
			: [pa] "m" (vmcs_pa)
			: "cc", "memory"
		);
		printk("vmptrld = %d\n", ret1);

		/* 
		（重要）
		为了规范对当前vmcs data部分的访问，intel提供了vmwrite，vmread指令
		这两个指令接受两个操作数，第一个操作数表示字段索引（不是偏移），第二个
		操作数表示要加载或者保存值的寄存器
		 */
		/* 
		（重要）
		vmcs_file索引的宏定义（完整内容见note.txt）：
		GUEST_CS_SELECTOR = 0x00000802,
		GUEST_TR_SELECTOR = 0x0000080e,
		VMCS_LINK_POINTER = 0x00002800,
		GUEST_CS_LIMIT = 0x00004802,
		GUEST_TR_LIMIT = 0x0000480e,
		…
		 */
		vmcs_field = 0x00000802; // guest cs段选择子值
		vmcs_field_value = 0x0000;
		asm volatile (
			"vmwrite %1, %0\n\t"
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Guest CS selctor = 0x%llx\n", vmcs_field_value);

		vmcs_field = 0x0000080E; // guest tr段选择子值
		vmcs_field_value = 0x0000;
		asm volatile (
			"vmwrite %1, %0\n\t"
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Guest TR selctor = 0x%llx\n", vmcs_field_value);

		vmcs_field = 0x00002800; // 设置vmcs link指针（啥玩意？）
		vmcs_field_value = 0xFFFFFFFFFFFFFFFF;
		asm volatile (
			"vmwrite %1, %0\n\t"
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("VMCS link pointer = 0x%llx\n", vmcs_field_value);

		vmcs_field = 0x00004802; // 设置guest cs段限制（指可用比特位范围）
		vmcs_field_value = 0x0000FFFF;
		asm volatile (
			"vmwrite %1, %0\n\t"
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Guest CS limit = 0x%llx\n", vmcs_field_value);

		vmcs_field = 0x0000480E; // 设置guest tr段限制（指可用比特位范围）
		vmcs_field_value = 0x0000000FF;
		asm volatile (
			"vmwrite %1, %0\n\t"
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Guest TR limit = 0x%llx\n", vmcs_field_value);

		vmcs_field = 0x00004814; // 设置guest es段权限
		vmcs_field_value = 0x00010000;
		asm volatile (
			"vmwrite %1, %0\n\t"
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Guest ES access rights = 0x%llx\n", vmcs_field_value);

		vmcs_field = 0x00004816; // 设置guest cs段权限
		vmcs_field_value = 0x0000009B;
		asm volatile (
			"vmwrite %1, %0\n\t"
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Guest CS access rights = 0x%llx\n", vmcs_field_value);

		vmcs_field = 0x00004818; // 设置guest ss段权限
		vmcs_field_value = 0x00010000;
		asm volatile (
			"vmwrite %1, %0\n\t"
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Guest SS access rights = 0x%llx\n", vmcs_field_value);

		vmcs_field = 0x0000481A; // 设置guest ds段权限
		vmcs_field_value = 0x00010000;
		asm volatile (
			"vmwrite %1, %0\n\t"
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Guest DS access rights = 0x%llx\n", vmcs_field_value);

		vmcs_field = 0x0000481C; // 设置guest fs段权限
		vmcs_field_value = 0x00010000;
		asm volatile (
			"vmwrite %1, %0\n\t"
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Guest FS access rights = 0x%llx\n", vmcs_field_value);

		vmcs_field = 0x0000481E; // 设置guest gs段权限
		vmcs_field_value = 0x00010000;
		asm volatile (
			"vmwrite %1, %0\n\t"
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Guest GS access rights = 0x%llx\n", vmcs_field_value);

		vmcs_field = 0x00004820; // 设置guest LDTR段权限
		vmcs_field_value = 0x00010000;
		asm volatile (
			"vmwrite %1, %0\n\t"
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Guest LDTR access rights = 0x%llx\n", vmcs_field_value);

		vmcs_field = 0x00004822; // 设置guest TR段权限
		vmcs_field_value = 0x0000008B;
		asm volatile (
			"vmwrite %1, %0\n\t"
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Guest TR access rights = 0x%llx\n", vmcs_field_value);

		vmcs_field =  0x00006800; // 设置guest CR0寄存器
		vmcs_field_value = 0x00000020;
		asm volatile (
			"vmwrite %1, %0\n\t"
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Guest CR0 = 0x%llx\n", vmcs_field_value);

		vmcs_field =  0x00006804; // 设置guest CR4寄存器
		vmcs_field_value = 0x0000000000002000;
		asm volatile (
			"vmwrite %1, %0\n\t"
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Guest CR4 = 0x%llx\n", vmcs_field_value);

		vmcs_field =  0x00006808; // 设置guest cs段基址
		vmcs_field_value = 0x0000000000000000;
		asm volatile (
			"vmwrite %1, %0\n\t"
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Guest CS base = 0x%llx\n", vmcs_field_value);

		vmcs_field =  0x00006814; // 设置guest TR段基址
		vmcs_field_value = 0x0000000000008000;
		asm volatile (
			"vmwrite %1, %0\n\t"
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Guest TR base = 0x%llx\n", vmcs_field_value);

		vmcs_field = 0x0000681E; // 设置guest RIP寄存器（执行流起始点！）
		vmcs_field_value = 0x0000000000000000;
		asm volatile (
			"vmwrite %1, %0\n\t"
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Guest RIP = 0x%llx\n", vmcs_field_value);

		vmcs_field = 0x00006820; // 设置guest RFLAGS寄存器
		vmcs_field_value = 0x0000000000000002;
		asm volatile (
			"vmwrite %1, %0\n\t"
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Guest RFLAGS = 0x%llx\n", vmcs_field_value);

		vmcs_field = 0x00000C00; // 设置host es段选择子
		asm volatile (
			"movq %%es, %0\n\t" // 取出host当前es值（这里是整个取出）
			: "=a" (vmcs_field_value)
			:
		);
		vmcs_field_value &= 0xF8; // 做与运算取出低位的段选择子部分
		asm volatile (
			"vmwrite %1, %0\n\t" // 把段选择子设置到vmcs的host_state_area->ES_SELECTOR中
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Host ES selctor = 0x%llx\n", vmcs_field_value);

		vmcs_field = 0x00000C02; // 设置host cs段选择子
		asm volatile (
			"movq %%cs, %0\n\t"
			: "=a" (vmcs_field_value)
			:
		);
		vmcs_field_value &= 0xF8;
		asm volatile (
			"vmwrite %1, %0\n\t" // 设置到vmcs的host_state_area->CS_SELECTOR中
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Host CS selctor = 0x%llx\n", vmcs_field_value);

		vmcs_field = 0x00000C04; // 设置host ss段选择子
		asm volatile (
			"movq %%ss, %0\n\t"
			: "=a" (vmcs_field_value)
			:
		);
		vmcs_field_value &= 0xF8;
		asm volatile (
			"vmwrite %1, %0\n\t" // 设置到vmcs的host_state_area->SS_SELECTOR中
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Host SS selctor = 0x%llx\n", vmcs_field_value);

		vmcs_field = 0x00000C06; // 设置host ds段选择子
		asm volatile (
			"movq %%ds, %0\n\t"
			: "=a" (vmcs_field_value)
			:
		);
		vmcs_field_value &= 0xF8;
		asm volatile (
			"vmwrite %1, %0\n\t" // 设置到vmcs的host_state_area->DS_SELECTOR中
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Host DS selctor = 0x%llx\n", vmcs_field_value);

		vmcs_field = 0x00000C08; // 设置host fs段选择子
		asm volatile (
			"movq %%fs, %0\n\t"
			: "=a" (vmcs_field_value)
			:
		);
		vmcs_field_value &= 0xF8;
		asm volatile (
			"vmwrite %1, %0\n\t" // 设置到vmcs的host_state_area->FS->SELECTOR中
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Host FS selctor = 0x%llx\n", vmcs_field_value);

		vmcs_field = 0x00000C0A; // 设置host gs段选择子
		asm volatile (
			"movq %%gs, %0\n\t"
			: "=a" (vmcs_field_value)
			:
		);
		vmcs_field_value &= 0xF8;
		asm volatile (
			"vmwrite %1, %0\n\t" // 设置到vmcs的host_state_area->GS->SELECTOR中
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Host GS selctor = 0x%llx\n", vmcs_field_value);

		vmcs_field = 0x00000C0C; // 设置host tr段选择子
		asm volatile (
			"str %0\n\t" // 读出host中的tr段寄存器值
			: "=a" (vmcs_field_value)
			:
		);
		vmcs_field_value &= 0xF8;
		asm volatile (
			"vmwrite %1, %0\n\t" // 设置到vmcs的host_state_area->TR->SELECTOR中
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Host TR selctor = 0x%llx\n", vmcs_field_value);

		vmcs_field = 0x00002C00; // 设置host IA32_PAT
		ecx = 0x277;
		asm volatile (
			"rdmsr\n\t" // 该值位于msr寄存器中，所以要先从msr寄存器给读出来（下同）
			: "=a" (eax), "=d" (edx)
			: "c" (ecx)
		);
		rdx = edx;
		vmcs_field_value = rdx << 32 | eax;
		asm volatile (
			"vmwrite %1, %0\n\t" // 设置到vmcs的host_state_area->IA32_PAT中
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Host IA32_PAT = 0x%llx\n", vmcs_field_value);

		vmcs_field = 0x00002C02; // 设置host IA32_EFER 
		ecx = 0xC0000080;
		asm volatile (
			"rdmsr\n\t"
			: "=a" (eax), "=d" (edx)
			: "c" (ecx)
		);
		rdx = edx;
		vmcs_field_value = rdx << 32 | eax;
		asm volatile (
			"vmwrite %1, %0\n\t" // 设置到vmcs的host_state_area->IA32_EFER中
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Host IA32_EFER = 0x%llx\n", vmcs_field_value);

		vmcs_field = 0x00002C04; // 设置host IA32_PERF_GLOBAL_CTRL
		ecx = 0x38F;
		asm volatile (
			"rdmsr\n\t"
			: "=a" (eax), "=d" (edx)
			: "c" (ecx)
		);
		rdx = edx;
		vmcs_field_value = rdx << 32 | eax;
		asm volatile (
			"vmwrite %1, %0\n\t" // 设置到vmcs的host_state_area->IA32_PERF_GLOBAL_CTRL中
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Host IA32_PERF_GLOBAL_CTRL = 0x%llx\n", vmcs_field_value);

		vmcs_field = 0x00004C00; // 设置host IA32_SYSENTER_CS
		ecx = 0x174;
		asm volatile (
			"rdmsr\n\t"
			: "=a" (eax), "=d" (edx)
			: "c" (ecx)
		);
		rdx = edx;
		vmcs_field_value = rdx << 32 | eax;
		asm volatile (
			"vmwrite %1, %0\n\t" // 设置到vmcs的host_state_area->IA32_SYSENTER_CS中
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Host IA32_SYSENTER_CS = 0x%llx\n", vmcs_field_value);

		vmcs_field = 0x00006C00; // 设置host CR0
		asm volatile (
			"movq %%cr0, %0\n\t"
			: "=a" (vmcs_field_value)
			:
		);
		asm volatile (
			"vmwrite %1, %0\n\t" // 设置到vmcs的host_state_area->CR0中
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Host CR0 = 0x%llx\n", vmcs_field_value);

		vmcs_field = 0x00006C02; // 设置host CR3
		asm volatile (
			"movq %%cr3, %0\n\t"
			: "=a" (vmcs_field_value)
			:
		);
		asm volatile (
			"vmwrite %1, %0\n\t" // 设置到vmcs的host_state_area->CR3中
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Host CR3 = 0x%llx\n", vmcs_field_value);

		vmcs_field = 0x00006C04; // 设置host CR4
		asm volatile (
			"movq %%cr4, %0\n\t"
			: "=a" (vmcs_field_value)
			:
		);
		asm volatile (
			"vmwrite %1, %0\n\t" // 设置到vmcs的host_state_area->CR4中
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Host CR4 = 0x%llx\n", vmcs_field_value);

		vmcs_field = 0x00006C06; // 设置host FS_BASE
		ecx = 0xC0000100;
		asm volatile (
			"rdmsr\n\t"
			: "=a" (eax), "=d" (edx)
			: "c" (ecx)
		);
		rdx = edx;
		vmcs_field_value = rdx << 32 | eax;
		asm volatile (
			"vmwrite %1, %0\n\t" // 设置到vmcs的host_state_area->FS->BASE中
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Host FS base = 0x%llx\n", vmcs_field_value);

		vmcs_field = 0x00006C08; // 设置host GS_BASE
		ecx = 0xC0000101;
		asm volatile (
			"rdmsr\n\t"
			: "=a" (eax), "=d" (edx)
			: "c" (ecx)
		);
		rdx = edx;
		vmcs_field_value = rdx << 32 | eax;
		asm volatile (
			"vmwrite %1, %0\n\t" // 设置到vmcs的host_state_area->GS->BASE中
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Host GS base = 0x%llx\n", vmcs_field_value);

		asm volatile (
			"str %0\n\t"
			: "=a" (host_tr_selector)
			:
		);
		host_tr_selector &= 0xF8;

		asm volatile (
			"sgdt %0\n\t"
			: "=m" (xdtr)
			:
		);
		host_gdt_base = *((u64 *) (xdtr + 2)); // 加一个偏移主要用于计算出GDT_BASE部分

		host_tr_desc = *((u64 *) (host_gdt_base + host_tr_selector));
		vmcs_field_value = ((host_tr_desc & 0x000000FFFFFF0000) >> 16) | ((host_tr_desc & 0xFF00000000000000) >> 32);

		host_tr_desc = *((u64 *) (host_gdt_base + host_tr_selector + 8));
		host_tr_desc <<= 32;
		vmcs_field_value |= host_tr_desc;

		vmcs_field = 0x00006C0A; // 设置host TR_BASE为host_tr_desc
		asm volatile (
			"vmwrite %1, %0\n\t"
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Host TR base = 0x%llx\n", vmcs_field_value);

		vmcs_field = 0x00006C0C; // 设置host GDTR_BASE
		asm volatile (
			"sgdt %0\n\t"
			: "=m" (xdtr)
			:
		);
		vmcs_field_value = *((u64 *) (xdtr + 2)); // 取得GDT_BASE部分的值
		asm volatile (
			"vmwrite %1, %0\n\t" // 设置到vmcs的host_state_area->GDTR_BASE中
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Host GDTR base = 0x%llx\n", vmcs_field_value);

		vmcs_field = 0x00006C0E; // 设置host IDTR_BASE
		asm volatile (
			"sidt %0\n\t"
			: "=m" (xdtr)
			:
		);
		vmcs_field_value = *((u64 *) (xdtr + 2)); // 取得IDT_BASE部分的值
		asm volatile (
			"vmwrite %1, %0\n\t" // 设置到vmcs的host_state_area->IDTR_BASE中
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Host IDTR base = 0x%llx\n", vmcs_field_value);

		vmcs_field = 0x00006C10; // 设置host IA32_SYSENTER_ESP
		ecx = 0x175;
		asm volatile (
			"rdmsr\n\t"
			: "=a" (eax), "=d" (edx)
			: "c" (ecx)
		);
		rdx = edx;
		vmcs_field_value = rdx << 32 | eax;
		asm volatile (
			"vmwrite %1, %0\n\t" // 设置到vmcs的host_state_area->IA32_SYSENTER_ESP中
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Host IA32_SYSENTER_ESP = 0x%llx\n", vmcs_field_value);

		/* 
		（重要）
		IA32_SYSENTER_EIP用于标识用户进行快速系统调用时，直接跳转到的ring0代码段的地址
		SYSENTER进行的系统调用可以避免普通中断产生的较大开销
		*/
		vmcs_field = 0x00006C12; // 设置host IA32_SYSENTER_EIP 
		ecx = 0x176;
		asm volatile (
			"rdmsr\n\t"
			: "=a" (eax), "=d" (edx)
			: "c" (ecx)
		);
		rdx = edx;
		vmcs_field_value = rdx << 32 | eax;
		asm volatile (
			"vmwrite %1, %0\n\t" // 设置到vmcs的host_state_area->IA32_SYSENTER_EIP中
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Host IA32_SYSENTER_EIP = 0x%llx\n", vmcs_field_value);

		stack = (u8 *) kmalloc(0x8000, GFP_KERNEL); // 通过kmalloc为host rsp指向的栈分配了空间
		vmcs_field = 0x00006C14; // 设置host RSP寄存器值
		vmcs_field_value = (u64) stack + 0x8000;
		asm volatile (
			"vmwrite %1, %0\n\t" // 设置到vmcs的host_state_area->RSP中
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Host RSP = 0x%llx\n", vmcs_field_value);

		/* 
		（很重要！）
		这一步把host RIP设置到_vmexit_handler，并且上一步设置好了host RSP
		这样当VM退出时就会进入_vmexit_handler处理逻辑，并使用先前分配的栈空间作为运行栈
		 */
		vmcs_field = 0x00006C16; // 设置host RIP寄存器值（很重要！）
		vmcs_field_value = (u64) _vmexit_handler; // 这里设置了从虚拟机中退出时要跳转到的地址
		asm volatile (
			"vmwrite %1, %0\n\t"
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Host RIP = 0x%llx\n", vmcs_field_value);

		vmcs_field = 0x00000000; // 设置VIRTUAL_PROCESSOR_ID值
		vmcs_field_value = 0x0001; // vCPU ID被设为常量1
		asm volatile (
			"vmwrite %1, %0\n\t"
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("VPID = 0x%llx\n", vmcs_field_value);

		/* 此处开始给虚拟机设置EPT表 */
		vmcs_field = 0x0000201A; // 设置EPT_POINTER的值
		vmcs_field_value = ept_pointer; // 注意ept_pointer指针指向一个保存了EPT表地址的内存位置（而不是直接指向EPT表）
		asm volatile (
			"vmwrite %1, %0\n\t"
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("EPT_POINTER = 0x%llx\n", vmcs_field_value);

		vmcs_field = 0x00004000; // 设置PIN_BASED_VM_EXEC_CONTROL的值
		vmcs_field_value = 0x00000016;
		asm volatile (
			"vmwrite %1, %0\n\t"
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Pin-based VM-execution controls = 0x%llx\n", vmcs_field_value);

		vmcs_field = 0x00004002; // 设置CPU_BASED_VM_EXEC_CONTROL的值
		vmcs_field_value = 0x840061F2;
		asm volatile (
			"vmwrite %1, %0\n\t"
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Primary Processor-based VM-execution controls = 0x%llx\n", vmcs_field_value);

		vmcs_field = 0x0000401E; // 设置SECONDARY_VM_EXEC_CONTROL的值
		vmcs_field_value = 0x000000A2;
		asm volatile (
			"vmwrite %1, %0\n\t"
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("Secondary Processor-based VM-execution controls = 0x%llx\n", vmcs_field_value);

		vmcs_field = 0x00004012; // 设置VM_ENTRY_CONTROLS的值
		vmcs_field_value = 0x000011fb;
		asm volatile (
			"vmwrite %1, %0\n\t"
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("VM-entry controls = 0x%llx\n", vmcs_field_value);

		vmcs_field = 0x0000400C; // 设置VM_EXIT_CONTROLS的值
		vmcs_field_value = 0x00036ffb;
		asm volatile (
			"vmwrite %1, %0\n\t"
			:
			: "r" (vmcs_field), "r" (vmcs_field_value)
		);
		printk("VM-exit controls = 0x%llx\n", vmcs_field_value);

		/* 此处保存正式进入虚拟机前的rsp和rbp */
		asm volatile (
			"movq %%rsp, %0\n\t"
			"movq %%rbp, %1\n\t"
			: "=a" (shutdown_rsp), "=b" (shutdown_rbp)
			:
		);

		/* 
		（非常重要！）
		执行VMLAUNCH指令，开始vCPU的执行。
		注意使用者需要通过VMM需要判断VMLAUNCH的返回结果，
		以确定vCPU是否真正被执行，还是因为某些逻辑冲突导致vCPU没有被执行就返回
		*/
		asm volatile (
			"vmlaunch\r\n" // 一切的准备都是为了最后vmlaunch进入客户机的vCPU
			"setna %[ret]"
			: [ret] "=rm" (ret1)
			:
			: "cc", "memory"
		);
		printk("vmlaunch = %d\n", ret1);

		/* 
		这一步主要是通过VM_EXIT_REASON判断虚拟机退出的原因
		 */
		vmcs_field = 0x00004402;
		asm volatile (
			"vmread %1, %0\n\t" // 读取VMCS中VM_EXIT_REASON域的值
			: "=r" (vmcs_field_value)
			: "r" (vmcs_field)
		);
		printk("EXIT_REASON = 0x%llx\n", vmcs_field_value); // 依照不同的退出原因是不是可以有不同的处理方式

		/*
		（重要！）
		注意一下这里用内联汇编定义了一个LABLE: shutdown
		默认情况下对HLT命令的handle会跳到这个标签
		*/
		asm volatile ("shutdown:");
		printk("********** guest shutdown **********\n");

		/* 关闭VMX操作模式 */
		asm volatile ("vmxoff"); 

		/* 设置cr4中第13位以关闭虚拟化开关 */
		asm volatile (
			"movq %cr4, %rax\n\t"
			"btr $13, %rax\n\t"
			"movq %rax, %cr4"
		);

		break;
	}

	return 0;
}

/* 
该函数用于实现从VM退出到VMM时的处理逻辑（此时VM上下文已经被保存过）
*/
void handle_vmexit(struct guest_regs *regs)
{
	u64 vmcs_field;
	u64 vmcs_field_value;
	u64 guest_rip;

	dump_guest_regs(regs); // dump客户机运行时的寄存器状态

	// 读出EXIT_REASON
	vmcs_field = 0x00004402;
	asm volatile (
		"vmread %1, %0\n\t"
		: "=r" (vmcs_field_value)
		: "r" (vmcs_field)
	);
	printk("EXIT_REASON = 0x%llx\n", vmcs_field_value);

	/* 
	（重要！）
	从读出的EXIT_REASON进入不同的处理逻辑，
	按照KVM的实现方式，用户可以自定义对于某些PMIO，MMIO以及系统中断的处理逻辑。
	*/
	// 各种EXIT_REASON的宏定义可以在note.txt中查看
	switch (vmcs_field_value) {
	case 0x0C: // EXIT_REASON_HLT
		/* 
		恢复先前保存的launch前的rsp和rbp指针，然后 
		跳转执行流到预先定义好的shutdown LABLE处
		*/
		asm volatile (
			"movq %0, %%rsp\n\t"
			"movq %1, %%rbp\n\t"
			"jmp shutdown\n\t"
			:
			: "a" (shutdown_rsp), "b" (shutdown_rbp)
		);

		break;

	case 0x0A: // EXIT_REASON_CPUID
		/* 遇到取cpuid时直接手动去设置寄存器值 */
		regs->rax = 0x6368;
		regs->rbx = 0x6561;
		regs->rcx = 0x70;

		break;

	default:
		break;
	}

	/* 每次重新进入guest VM之前都要重新设置一下GUEST_RIP */
	/* 读取VM退出时的rip地址 */
	vmcs_field = 0x0000681E; // 读取GUEST_RIP
	asm volatile (
		"vmread %1, %0\n\t"
		: "=r" (vmcs_field_value)
		: "r" (vmcs_field)
	);
	printk("Guest RIP = 0x%llx\n", vmcs_field_value);

	guest_rip = vmcs_field_value;
	/* 读取导致VM退出的指令的长度 */
	vmcs_field = 0x0000440C; // 读取VM_EXIT_INSTRUCTION_LEN
	asm volatile (
		"vmread %1, %0\n\t"
		: "=r" (vmcs_field_value)
		: "r" (vmcs_field)
	);
	printk("VM-exit instruction length = 0x%llx\n", vmcs_field_value);

	/* 
	（重要！）
	重新设置VM的rip跳过导致退出的指令的长度，否则恢复执行流时会再次退出！ 
	从这里可以看出一个很重要的点就是：RIP遇到执行到导致VM退出到VMM的指令
	并不会自动递增，需要VMM的编写者依据实际情况来决定——是要跳过该指令继
	续原来的执行流，还是就此中断VM客户机的执行。比如遇到HLT指令理应结束
	VM的执行，而遇到一些端口IO则需要在IO完成后恢复执行流！
	*/
	vmcs_field = 0x0000681E; // 设置GUEST_RIP
	vmcs_field_value = guest_rip + vmcs_field_value;
	asm volatile (
		"vmwrite %1, %0\n\t"
		:
		: "r" (vmcs_field), "r" (vmcs_field_value)
	);
	printk("Guest RIP = 0x%llx\n", vmcs_field_value);

	return;
}

/* 
初始化EPT各级表：
EPTP+PA--PML4->EPT page-directory pointer->EPT page-directory->EPT Page->Page
*/
static void init_ept(u64 *ept_pointer, u64 guest_memory_pa)
{
	int i;

	u64 ept_va; // ept虚拟地址
	u64 ept_pa; // ept物理地址

	u64 *entry; // 临时变量，作为各级页表的入口点

	// 使用kmalloc拿到用于存放EPT各级页表的内存
	ept_memory = (u8 *) kmalloc(EPT_MEMORY_SIZE, GFP_KERNEL);
	memset(ept_memory, 0, EPT_MEMORY_SIZE);

	// 设置ept虚拟地址为ept_memory 并通过__pa宏转换为ept物理地址
	ept_va = (u64) ept_memory;
	ept_pa = __pa(ept_memory);

	// 初始化ept指针
	init_ept_pointer(ept_pointer, ept_pa);

	/* 
	往下初始化各级页表表项
	每个表的大小都是4K
	并且在连续内存上分布(4K间隔)
	*/

	/* 
	注意，进行写操作的时候都是用va作为指针，但是写进去的值都是pa，
	因为EPT是要从客户机物理内存直通主机物理内存的 
	*/

	/* 将entry设置为PML4表入口 */
	entry = (u64 *) ept_va;
	/* 为PML4表添加一个EPT page-directory pointer表项 */
	init_pml4e(entry, ept_pa + 0x1000);
	printk("pml4e = 0x%llx\n", *entry);

	/* 将entry设置为EPT page-directory pointer表入口 */
	entry = (u64 *) (ept_va + 0x1000);
	/* 为EPT page-directory pointer表添加一个EPT page-directory表项 */
	init_pdpte(entry, ept_pa + 0x2000);
	printk("pdpte = 0x%llx\n", *entry);

	/* 将entry设置为EPT page-directory表入口 */
	entry = (u64 *) (ept_va + 0x2000);
	/* 为EPT page-directory表添加一个EPT Page表项 */
	init_pde(entry, ept_pa + 0x3000);
	printk("pdte = 0x%llx\n", *entry);

	/* 遍历EPT Page表前16个表项设置Page地址 */
	for (i = 0; i < 16; i++) {
		entry = (u64 *) (ept_va + 0x3000 + i * 8); // 将entry设置为每个表项的入口
		init_pte(entry, guest_memory_pa + i * 0x1000); // 设置EPT Page表项
		printk("pte = 0x%llx\n", *entry);
	}

	/* 以上除了EPT Page表之外的每个表都只有一个表项，所以最大管理内存为512GB */

	return;
}

static void init_ept_pointer(u64 *p, u64 pa)
{
	*p = pa | 1 << 6 | 3 << 3 | 6;

	return;
}

/* 
 PML4表项的低三位分别控制rwx权限
*/
static void init_pml4e(u64 *entry, u64 pa)
{
	*entry = pa | 1 << 2 | 1 << 1 | 1;

	return;
}

static void init_pdpte(u64 *entry, u64 pa)
{
	*entry = pa | 1 << 2 | 1 << 1 | 1;

	return;
}

static void init_pde(u64 *entry, u64 pa)
{
	*entry = pa | 1 << 2 | 1 << 1 | 1;

	return;
}

static void init_pte(u64 *entry, u64 pa)
{
	*entry = pa | 6 << 3 | 1 << 2 | 1 << 1 | 1;

	return;
}

static void dump_guest_regs(struct guest_regs *regs)
{
	printk("********** guest regs **********\n");
	printk("* rax = 0x%llx\n", regs->rax);
	printk("* rcx = 0x%llx\n", regs->rcx);
	printk("* rdx = 0x%llx\n", regs->rdx);
	printk("* rbx = 0x%llx\n", regs->rbx);
	printk("* rbp = 0x%llx\n", regs->rbp);
	printk("* rsi = 0x%llx\n", regs->rsi);
	printk("* rdi = 0x%llx\n", regs->rdi);
	printk("* r8 = 0x%llx\n", regs->r8);
	printk("* r9 = 0x%llx\n", regs->r9);
	printk("* r10 = 0x%llx\n", regs->r10);
	printk("* r11 = 0x%llx\n", regs->r11);
	printk("* r12 = 0x%llx\n", regs->r12);
	printk("* r13 = 0x%llx\n", regs->r13);
	printk("* r14 = 0x%llx\n", regs->r14);
	printk("* r15 = 0x%llx\n", regs->r15);
	printk("********************************\n");
}

module_init(peach_init);
module_exit(peach_exit);
