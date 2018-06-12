# lab4 作业报告

## 介绍

在本实验中，我们将在多个同时活动的用户模式环境中执行抢先式多任务处理。
在Part A中，我们将向JOS添加多处理器支持，实施循环调度，并添加基本的环境管理系统调用（创建和销毁环境以及分配/映射内存的调用）。
在Part B中， 我们将实现一个类Unix的fork（），它允许用户模式环境创建它自己的副本。
最后，在Part C中，我们将添加对进程间通信（IPC）的支持，允许不同的用户模式环境进行明确的通信和同步。 我们还将添加对硬件时钟中断和抢占的支持。  

## Part A

扩展jos的功能,让它能在多核处理器上运行,实现一些新的 jos 内核的系统调用,来允许用户态创建新的环境,实现一个合作循环调度.允许内核 在不同的环境中切换,如果当前的环境自愿放弃CPU/或结束运行.在之后的Part C将会实现抢占方式调度,能让内核在一个确定的时间间隔收回CPU的使用权。

### Exercise 1

修改kern/pmap.c 中的page_init()  

```c
void
page_init(void)
{
	// LAB 4:
	// Change your code to mark the physical page at MPENTRY_PADDR
	// as in use

	// The example code here marks all physical pages as free.
	// However this is not truly the case.  What memory is free?
	//  1) Mark physical page 0 as in use.
	//     This way we preserve the real-mode IDT and BIOS structures
	//     in case we ever need them.  (Currently we don't, but...)
	//  2) The rest of base memory, [PGSIZE, npages_basemem * PGSIZE)
	//     is free.
	//  3) Then comes the IO hole [IOPHYSMEM, EXTPHYSMEM), which must
	//     never be allocated.
	//  4) Then extended memory [EXTPHYSMEM, ...).
	//     Some of it is in use, some is free. Where is the kernel
	//     in physical memory?  Which pages are already in use for
	//     page tables and other data structures?
	//
	// Change the code to reflect this.
	// NB: DO NOT actually touch the physical memory corresponding to
	// free pages!
        pages[0].pp_ref = 1;
	pages[0].pp_link = NULL;
	size_t i;
	for (i = 1; i < npages_basemem; i++) {
                if (i == MPENTRY_PADDR / PGSIZE) {
                    pages[i].pp_ref = 1;
                    pages[i].pp_link = NULL;
                    continue;
                }

		pages[i].pp_ref = 0;
		pages[i].pp_link = page_free_list;
		page_free_list = &pages[i];
	}
        for (i = PGNUM(PADDR(boot_alloc(0))); i < npages; i++) {
		pages[i].pp_ref = 0;
		pages[i].pp_link = page_free_list;
		page_free_list = &pages[i];
	}
        
	chunk_list = NULL;
}
```

### Exercise 2

修改kern/pamp.c 里面的mem_init_mp()  

```c
static void
mem_init_mp(void)
{
	// Create a direct mapping at the top of virtual address space starting
	// at IOMEMBASE for accessing the LAPIC unit using memory-mapped I/O.
	boot_map_region(kern_pgdir, IOMEMBASE, -IOMEMBASE, IOMEM_PADDR, PTE_W);

	// Map per-CPU stacks starting at KSTACKTOP, for up to 'NCPU' CPUs.
	//
	// For CPU i, use the physical memory that 'percpu_kstacks[i]' refers
	// to as its kernel stack. CPU i's kernel stack grows down from virtual
	// address kstacktop_i = KSTACKTOP - i * (KSTKSIZE + KSTKGAP), and is
	// divided into two pieces, just like the single stack you set up in
	// mem_init:
	//     * [kstacktop_i - KSTKSIZE, kstacktop_i)
	//          -- backed by physical memory
	//     * [kstacktop_i - (KSTKSIZE + KSTKGAP), kstacktop_i - KSTKSIZE)
	//          -- not backed; so if the kernel overflows its stack,
	//             it will fault rather than overwrite another CPU's stack.
	//             Known as a "guard page".
	//     Permissions: kernel RW, user NONE
	//
    int i;
    for(i = 0; i < NCPU; ++i )
        boot_map_region(kern_pgdir, KSTACKTOP - i * (KSTKSIZE + KSTKGAP) - KSTKSIZE, KSTKSIZE, PADDR(percpu_kstacks[i]), PTE_W);
    }
```

### Exercise 3

修改kern/trap.c 里面的trap_init_percpu()  

```c
void
trap_init_percpu(void)
{
	// The example code here sets up the Task State Segment (TSS) and
	// the TSS descriptor for CPU 0. But it is incorrect if we are
	// running on other CPUs because each CPU has its own kernel stack.
	// Fix the code so that it works for all CPUs.
	//
	// Hints:
	//   - The macro "thiscpu" always refers to the current CPU's
	//     struct Cpu;
	//   - The ID of the current CPU is given by cpunum() or
	//     thiscpu->cpu_id;
	//   - Use "thiscpu->cpu_ts" as the TSS for the current CPU,
	//     rather than the global "ts" variable;
	//   - Use gdt[(GD_TSS0 >> 3) + i] for CPU i's TSS descriptor;
	//   - You mapped the per-CPU kernel stacks in mem_init_mp()
	//
	// ltr sets a 'busy' flag in the TSS selector, so if you
	// accidentally load the same TSS on more than one CPU, you'll
	// get a triple fault.  If you set up an individual CPU's TSS
	// wrong, you may not get a fault until you try to return from
	// user space on that CPU.

	// Setup a TSS so that we get the right stack
	// when we trap to the kernel.
    int index = thiscpu->cpu_id;
    thiscpu->cpu_ts.ts_esp0 = KSTACKTOP - index * (KSTKSIZE + KSTKGAP);
    thiscpu->cpu_ts.ts_ss0  = GD_KD;

    extern void sysenter_handler();
    wrmsr(0x174, GD_KT, 0);                   /* SYSENTER_CS_MSR */
    wrmsr(0x175, thiscpu->cpu_ts.ts_esp0 , 0);/* SYSENTER_ESP_MSR */
    wrmsr(0x176, (uint32_t)&sysenter_handler, 0);        /* SYSENTER_EIP_MSR */

    // Initialize the TSS slot of the gdt.
    int GD_TSSi = GD_TSS0 + (index << 3);
	gdt[GD_TSSi >> 3] = SEG16(STS_T32A, (uint32_t) (&(thiscpu->cpu_ts)),
      sizeof(struct Taskstate), 0);
	gdt[GD_TSSi >> 3].sd_s = 0;

	// Load the TSS selector (like other segment selectors, the
	// bottom three bits are special; we leave them 0)
	ltr(GD_TSSi);

	// Load the IDT
	lidt(&idt_pd);
}

```

### Exercise 4 Locking

解决多核同时运行的竞争状态,最简单的实现方法是用一个大的kernel lock, kern/spinlock.c实现了一个自旋锁。

加锁：

- `init.c i386_init()` 在`BSP wakes up the other CPUs`时 申请锁
- `init.c mp_main()`  在初始化AP后申请锁 并调用`sched_yield()`来开始在该AP上运行 环境.
- `trap.c trap()` 当从user mode trap申请锁. 通过`tf_cs`来检测当前处于用户态还是内核态.
- `env.c env_run()` 在切换到用户态前 的最后时刻 释放锁.不要释放得过早 或 过晚,否则你可能遇到 资源竞争或者死锁.

### Exercise 5 实现Round-Robin 调度

从当前运行的 env 开始，遍历所有的 env，遇到第一个可运行的 env 后，调度这个 env。如果没有找到，且之前运行的 env 依然为 RUNNING，则运行之 前的 env。同时，修改 syscall 中的 sys_yield，让其调用 sched_yield，这样就实现了 CPU 不同 env 间的调度。

kern/sched.c 

```c
void
sched_yield(void)
{
	struct Env *idle;
	int i;

	// Implement simple round-robin scheduling.
	//
	// Search through 'envs' for an ENV_RUNNABLE environment in
	// circular fashion starting just after the env this CPU was
	// last running.  Switch to the first such environment found.
	//
	// If no envs are runnable, but the environment previously
	// running on this CPU is still ENV_RUNNING, it's okay to
	// choose that environment.
	//
	// Never choose an environment that's currently running on
	// another CPU (env_status == ENV_RUNNING) and never choose an
	// idle environment (env_type == ENV_TYPE_IDLE).  If there are
	// no runnable environments, simply drop through to the code
	// below to switch to this CPU's idle environment.
    envid_t env_id = curenv == NULL ? 0 : ENVX(curenv->env_id);
    for(i = (env_id + 1) % NENV; i != env_id; i = (i + 1) % NENV){
      if(envs[i].env_type != ENV_TYPE_IDLE && envs[i].env_status == ENV_RUNNABLE) {
        env_run(&envs[i]);
      }
    }
    if(curenv && curenv->env_type != ENV_TYPE_IDLE && curenv->env_status == ENV_RUNNING){
      env_run(curenv);
    }

	// For debugging and testing purposes, if there are no
	// runnable environments other than the idle environments,
	// drop into the kernel monitor.
	for (i = 0; i < NENV; i++) {
		if (envs[i].env_type != ENV_TYPE_IDLE &&
		    (envs[i].env_status == ENV_RUNNABLE ||
		     envs[i].env_status == ENV_RUNNING))
			break;
	}
	if (i == NENV) {
		cprintf("No more runnable environments!\n");
		while (1)
			monitor(NULL);
	}

	// Run this CPU's idle environment when nothing else is runnable.
	idle = &envs[cpunum()];
	if (!(idle->env_status == ENV_RUNNABLE || idle->env_status == ENV_RUNNING))
		panic("CPU %d: No idle environment!", cpunum());
	env_run(idle);
}
```

除此之外，还需要在syscall.c里面添加调度。

### Exercise 6

这里实现了JOS里面的fork操作，和Linux的fork没有区别。

首先是sys_exofork(),，主要就是父进程先给子进程创建一个Env结构，并且标记为不可执行，因为这个时候还没c初始化完子进程。并且子进程的返回值是0，父进程的返回值是子进程的env_id，这和定义一样。第二个实现的是sys_env_set_status()，主要是设置子进程的状态是否可执行，就像函数名一样，没什么特别要说明的。第三个实现的是sys_page_alloc()，函数功能跟名字一样，给子进程分配物理页。第四个实现sys_page_map，实现共享地址映射的过程，和上面一个一样错误判断分支比较多比较烦，但是注释很详细。最后一个要实现的sys_page_unmap，故名思议和上面一个相反把映射解除掉，这个比较简短，错误判断少，而且还提示了调用page_remove()。



## Part B

### Exercise 7

这个函数的功能是注册一个handle函数，在发生了pgfault的时候调用该函数处理，是实现整个过程的初始函数注册阶段。 先获取对应的envid的struct Env，然后将handle函数赋给它的env_pgfault_upcall指针。当然这里还需要处理envid2env失败的情况。

```c
static int
sys_env_set_pgfault_upcall(envid_t envid, void *func)
{
  struct Env *e;
  int r;
  if((r = envid2env(envid, &e, 1)) < 0 )
    return r;
  e->env_pgfault_upcall = func;
  return 0;
}
```

### Exercise 8

流程

1. 用户环境发生页错误
2. trap进内核 并且 分发到 `page_fault_handler`
3. `page_fault_handler` 该函数 判断错误来源,即 是`page_fault_handler`过程中产生的 还是用户产生的
4. 如果是用户产生的 则,把当前的用户的tf 中需要的数据 放入UTrapframe(加上错误的va),修改 tf 的 eip(执行的代码位置 具体的处理代码) esp(使用的堆栈位置)
5. 这样就可以调用具体的处理 代码,而且和原来的用户进程 在 同一个进程里,只是切换了 eip,esp,它有访问原来进程所有可访问的权限,又在用户态
6. 如果 刚刚是`page_fault_handler`产生的,则 递归方式 fix,需要push栈开始的位置 将不再是`UXSTACKTOP` 而是`tf_esp` [需要多一个 word来存地址！！ 因为在发生fault时 硬件向当前栈push了一个 而递归的话 也就是在UXSTACK这个栈中push的 也就是下面的`-sizeof(void *)`]

```c
if (curenv->env_pgfault_upcall) {
  struct UTrapframe * utf;
  if ((uint32_t)(UXSTACKTOP - tf->tf_esp) < PGSIZE)
    utf = (struct UTrapframe *)(tf->tf_esp - sizeof(void *) - sizeof(struct UTrapframe));
  else
    utf = (struct UTrapframe *)(UXSTACKTOP - sizeof(struct UTrapframe));
  user_mem_assert(curenv, (void *)utf, sizeof(struct UTrapframe), PTE_W);

  utf->utf_fault_va = fault_va;
  utf->utf_err      = tf->tf_err;
  utf->utf_regs     = tf->tf_regs;
  utf->utf_eip      = tf->tf_eip;
  utf->utf_eflags   = tf->tf_eflags;
  utf->utf_esp      = tf->tf_esp;

  curenv->env_tf.tf_eip = (uintptr_t)curenv->env_pgfault_upcall;
  curenv->env_tf.tf_esp = (uintptr_t)utf;
  env_run(curenv);
}
```

### Exercise 9

写汇编。。。

```c
// Push old eip to old stack
// Set utf->utf_esp = old stack bottom - 4
movl 0x28(%esp), %ebx   // ebx = utf->utf_eip
movl 0x30(%esp), %eax
subl $0x4, %eax         // eax = utf->utf_esp - 4
movl %ebx, (%eax)       // *(utf->utf_esp - 4) = utf->utf_eip
movl %eax, 0x30(%esp)   // utf->utf_esp = utf->utf_esp - 4

// Restore the trap-time registers.  After you do this, you
// can no longer modify any general-purpose registers.
addl $0x8, %esp
popal                   // hardware utf_regs = urf->utf_regs

// Restore eflags from the stack.  After you do this, you can
// no longer use arithmetic operations or anything else that
// modifies eflags.
addl $0x4, %esp
popfl                   // hardware utf_eflags = urf->utf_eflags

// Switch back to the adjusted trap-time stack.
popl %esp

// Return to re-execute the instruction that faulted.
ret
```

### Exercise 10

```c
void
set_pgfault_handler(void (*handler)(struct UTrapframe *utf))
{
  int r;

  if (_pgfault_handler == 0) {
    // First time through!
    if((r = sys_page_alloc((envid_t) 0, (void*)(UXSTACKTOP-PGSIZE), PTE_U | PTE_P | PTE_W)) < 0 )
      panic("set_pgfault_handler %e\n",r);
    if((r = sys_env_set_pgfault_upcall((envid_t)0, _pgfault_upcall)) < 0)
      panic("sys_env_set_pgfault_upcall: %e\n", r);
  }

  // Save handler pointer for assembly to call.
  _pgfault_handler = handler;
}
```



### Exercise 11

接下来完成fork，这个fork和前面part A完成的fork的流程有一部分是相似的。fork函数首先在下面代码所示的第8行调用set_pgfault_handler函数将page fault的handle设置成自己定义的函数，随后在第10行调用sys_exofork创建子进程。11到17行进行错误判断处理。
接下来的循环是在父进程中进行的，遍历UTOP一下的空间，调用duppage函数映射到子进程并标记为写时复制。需要注意的是19行判断UXSTACK所在的PGSIZE空间是不能被映射的。随后父进程还需要给子进行分配一个PGSIZE的空间给用户异常栈作为起始使用，并且每个接下来调用的syscall都进行下错误处理增强鲁棒性，也便与调试。 

```c
envid_t
fork(void)
{
  set_pgfault_handler(pgfault);

  envid_t envid;
  uintptr_t addr;
  int r;
  // Allocate a new child environment.
  // The kernel will initialize it with a copy of our register state,
  // so that the child will appear to have called sys_exofork() too -
  // except that in the child, this "fake" call to sys_exofork()
  // will return 0 instead of the envid of the child.
  envid = sys_exofork();
  if (envid < 0)
    panic("sys_exofork: %e", envid);
  if (envid == 0) {
    // We're the child.
    // The copied value of the global variable 'thisenv'
    // is no longer valid (it refers to the parent!).
    // Fix it and return 0.
    thisenv = &envs[ENVX(sys_getenvid())];
    return 0;
  }
  // We're the parent.
  // Do the same mapping in child's process as parent
  // Search from UTEXT to USTACKTOP map the PTE_P | PTE_U page
  for (addr = UTEXT; addr < USTACKTOP; addr += PGSIZE)
    if ((vpd[PDX(addr)] & PTE_P) && (vpt[PGNUM(addr)] & (PTE_P | PTE_U)) == (PTE_P | PTE_U))
      duppage(envid, PGNUM(addr));

  if((r = sys_page_alloc(envid, (void *)(UXSTACKTOP-PGSIZE), PTE_U|PTE_W|PTE_P)) < 0)
    panic("sys_page_alloc: %e\n",r);
  if((r = sys_env_set_pgfault_upcall(envid, _pgfault_upcall)) < 0)
    panic("sys_env_set_pgfault_upcall: %e\n",r);

  if((r = sys_env_set_status(envid, ENV_RUNNABLE)) < 0)
    panic("sys_env_set_status: %e\n",r);
  return envid;
}
```

## Part C

让kernel

1. 能抢占不合作的环境
2. 允许环境之间 显示的交流/传递信息

### Exercise 12

和Lab3的中断一样，添加IRQ首先需要在kern/trapentry.S中注册对应的中断和handle函数名。然后在kern/trap.c的trap_init()函数中也同样模仿Lab3的做法先extern函数，然后调用SETGATE绑定。

### Exercise 13

```c
if (tf->tf_trapno == IRQ_OFFSET + IRQ_TIMER) {
  lapic_eoi();
  sched_yield();
  return;
}
```

### Exercise 14

实现IPC

1. 在kern/syscall.c里面添加路由
2. kern/syscall.c sys_ipc_recv()  

```c
static int
sys_ipc_recv(void *dstva)
{
  if(!(dstva < (void*)UTOP) || !PGOFF(dstva)){
    curenv->env_ipc_recving = 1;
    curenv->env_ipc_dstva   = dstva;
    curenv->env_status      = ENV_NOT_RUNNABLE;
    sched_yield();
    return 0;
  }
  return -E_INVAL;
}
```

3. ​

```c
static int
sys_ipc_try_send(envid_t envid, uint32_t value, void *srcva, unsigned perm)
{
  struct Env *e;
  int r;
  if((r = envid2env(envid, &e, 0) ) < 0)
    return r;
  if(!e->env_ipc_recving)
    return -E_IPC_NOT_RECV;
  if(srcva < (void*)UTOP){
    if(PGOFF(srcva) || (perm & (PTE_U | PTE_P)) != (PTE_U | PTE_P) || (perm & (~PTE_SYSCALL)))
      return -E_INVAL;
    pte_t *pte;
    struct Page *pg;
    if(!(pg = page_lookup(curenv->env_pgdir, srcva, &pte)))
      return -E_INVAL;
    if((*pte & perm) != perm)
      return -E_INVAL;
    if(e->env_ipc_dstva < (void *)UTOP){
      if((r = page_insert(e->env_pgdir, pg, e->env_ipc_dstva, perm)) < 0)
        return r;
    }
  }
  e->env_ipc_recving        = 0;
  e->env_ipc_from           = curenv->env_id;
  e->env_ipc_value          = value;
  e->env_ipc_perm           = perm;
  e->env_status             = ENV_RUNNABLE;
  e->env_tf.tf_regs.reg_eax = 0;
  return 0;
}
```

4. ​

```c
int32_t
ipc_recv(envid_t *from_env_store, void *pg, int *perm_store)
{
  if(!pg)
    pg = (void*)UTOP;
  int32_t r = sys_ipc_recv(pg);
  if(r >= 0) {
    if(perm_store)
      *perm_store = thisenv->env_ipc_perm;
    if(from_env_store)
      *from_env_store = thisenv->env_ipc_from;
    return thisenv->env_ipc_value;
  }
  if(perm_store)
    *perm_store = 0;
  if(from_env_store)
    *from_env_store = 0;
  return r;
}
```

