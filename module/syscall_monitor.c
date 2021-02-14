#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/tracepoint.h>
#include <linux/slab.h>
#include <asm/syscall.h>
#include <net/netlink.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/sysctl.h>
#include <trace/syscall.h>

#include "syscall_monitor.h"

#define NETLINK_SYSMON (MAX_LINKS - 1)
#define MAX_STACK_SYSMON_DEPTH 64
#define LEVEL_EMERG     0    /* system is unusable */
#define LEVEL_ALERT     1    /* action must be taken immediately */
#define LEVEL_CRIT      2    /* critical conditions */
#define LEVEL_ERR       3    /* error conditions */
#define LEVEL_WARNING   4    /* warning conditions */
#define LEVEL_NOTICE    5    /* normal but significant condition */
#define LEVEL_INFO      6    /* informational */
#define LEVEL_DEBUG     7    /* debug-level messages */
#define DEBUG_PRINT(level, format, ...) \
	if(level <= syscall_monitor_debug_level) \
		printk("syscall_monitor: "format"", ##__VA_ARGS__)

static int syscall_monitor_max_count = 256;
static struct list_head syscall_monitor_point_head[NR_syscalls];
static atomic_t syscall_monitor_count[NR_syscalls];
static struct kmem_cache *syscall_monitor_point_cachep;
static struct kmem_cache *syscall_monitor_timer_cachep;
static struct sock *syscall_monitor_sk;
static DEFINE_MUTEX(syscall_monitor_mutex);

static struct kmem_cache *syscall_monitor_record_cachep;
static struct list_head syscall_monitor_record_head[NR_syscalls];
static spinlock_t syscall_monitor_record_lock[NR_syscalls];
static int syscall_monitor_flush_record_count = 256;
static int syscall_monitor_current_record_count[NR_syscalls];
static struct task_struct *syscall_monitor_task;
static int syscall_monitor_sleep_second = 10;
static int syscall_monitor_sleep_second_min = 1;
static int syscall_monitor_sleep_second_max = 60;

struct ctl_table_header *syscall_monitor_table_head;
static int syscall_monitor_debug_level = 0;
static int syscall_monitor_debug_level_min = 0;
static int syscall_monitor_debug_level_max = 7;

/*
   static DEFINE_PER_CPU(struct list_head, syscall_monitor_point_cache);
   static DEFINE_PER_CPU(struct task_struct *, ksysmond);


   static int ksysmond_should_run(unsigned int cpu)
   {
   return !list_empty(this_cpu_ptr(&syscall_monitor_point_cache));
   }

   static int void run_ksysmond(unsigned int cpu)
   {
   struct list_head *list = this_cpu_ptr(&syscall_monitor_point_cache);
   struct syscall_monitor_point_struct *point, *pnext;
   struct syscall_monitor_timer_struct *timer, *tnext;

   list_for_each_entry_safe(point, pnext, list, syscall_list)
   {
   spin_lock(&point->timer_lock);
   list_for_each_entry_safe(timer, tnext, &point->timer_list, list)
   {
   hrtimer_cancel(timer);
   }
   spin_unlock(&point->timer_lock);
   }
   }

   static struct smp_hotplug_thread ksysmond_threads = {
   .store                  = &ksysmond,
   .thread_should_run      = ksoftirqd_should_run,
   .thread_fn              = run_ksoftirqd,
   .thread_comm            = "ksysmond/%u",
   };
   */


static struct ctl_table syscall_monitor_table[] = {
	{
		.procname =     "debug_level",
		.data =         &syscall_monitor_debug_level,
		.maxlen =       sizeof(int),
		.mode =         0644,
		.proc_handler = proc_dointvec_minmax,
		.extra1 =       &syscall_monitor_debug_level_min,
		.extra2 =       &syscall_monitor_debug_level_max,
	},
	{
		.procname =     "sleep_second",
		.data =         &syscall_monitor_sleep_second,
		.maxlen =       sizeof(int),
		.mode =         0644,
		.proc_handler = proc_dointvec_minmax,
		.extra1 =       &syscall_monitor_sleep_second_min,
		.extra2 =       &syscall_monitor_sleep_second_max,
	},
	{}
};

static struct syscall_metadata **fsyscalls_metadata;
static const char *syscall_nr_to_meta(int nr)
{
	if (!fsyscalls_metadata || nr >= NR_syscalls || nr < 0)
		return "nosymbol";

	return fsyscalls_metadata[nr]->name;
}

static char *trans_task_state(unsigned int state)
{       
	switch(state)
	{
		case 0x0:
			return "running";
		case 0x01:
			return "sleeping";
		case 0x02:
			return "disk sleep";
		case 0x04:
			return "stopped";
		case 0x08:
			return "tracing stop";
		default:
			return "unknown";
	}
	return "unknown";
}


static int register_trace_probe(const char *sym, void *probe, void *data)
{
	int ret;
	struct tracepoint *tp;
	char tracepoint_sym[128];

	sprintf(tracepoint_sym, "__tracepoint_%s", sym);
	tp = (struct tracepoint *)kallsyms_lookup_name(tracepoint_sym);
	if(!tp)
	{
		printk("Couldn't find tracepoint: %s\n", sym);
		return -EINVAL;
	}

	ret = tracepoint_probe_register(tp, probe, data);
	if(ret)
	{
		printk("Couldn't activate tracepoint: %s\n", sym);
		return ret;
	}

	return 0;
}

static void unregister_trace_probe(const char *sym, void *probe, void *data)
{       
	struct tracepoint *tp;
	char tracepoint_sym[128];

	sprintf(tracepoint_sym, "__tracepoint_%s", sym);
	tp = (struct tracepoint *)kallsyms_lookup_name(tracepoint_sym);
	if(!tp)
	{
		printk("Couldn't find tracepoint: %s\n", sym);
		return;
	}

	tracepoint_probe_unregister(tp, probe, data);

}

static struct sk_buff *syscall_monitor_skb(unsigned int seq, void *payload, int len)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;

	skb = nlmsg_new(len, GFP_ATOMIC);
	if(skb == NULL)
		return NULL;

	nlh = nlmsg_put(skb, 0, seq, 0, len, 0);
	if (nlh == NULL) 
	{
		kfree_skb(skb);
		return NULL;
	}

	memcpy(nlmsg_data(nlh), payload, len);

	nlmsg_end(skb, nlh);

	return skb;
}

//call need rcu, 在netlink中可以随意使用，但在系统调用上下文需要完全包含rcu锁
static struct syscall_monitor_point_struct *syscall_monitor_find_rcu(unsigned int syscallno, struct syscall_monitor_object_struct *object)
{
	struct syscall_monitor_point_struct *point;

	list_for_each_entry_rcu(point, &syscall_monitor_point_head[syscallno], syscall_list) 
	{
		if(point->object.type == object->type)
		{
			switch(object->type)
			{
				case TYPE_PID:
					if(point->object.pid == object->pid)
						goto find;
					break;
				case TYPE_TGID:
					if(point->object.tgid == object->tgid)
						goto find;
					break;
				case TYPE_COMM:
					if(strcmp(point->object.comm, object->comm) == 0)
						goto find;
					break;
				case TYPE_ALL:
					return NULL;
				default:
					BUG();
			}
		}
	}

	return NULL;
find:
	return point;
}

static struct sk_buff *syscall_monitor_add(struct nlmsghdr *nlh)
{
	struct syscall_monitor_recv_msg_struct *recv_msg;
	struct syscall_monitor_point_struct *point;
	struct syscall_monitor_send_msg_struct send_msg;

	send_msg.ops = OPS_ADD;
	send_msg.retnum = 0;
	recv_msg = (struct syscall_monitor_recv_msg_struct *)nlmsg_data(nlh);

	if(atomic_read(syscall_monitor_count + recv_msg->syscallno) > syscall_monitor_max_count)
	{
		send_msg.errno = RET_OVER_COUNT;
		goto err;
	}

	rcu_read_lock();
	point = syscall_monitor_find_rcu(recv_msg->syscallno, &recv_msg->object);
	if(point)
	{
		rcu_read_unlock();
		send_msg.errno = RET_CONFLICT;
		goto err;
	}
	rcu_read_unlock();

	point = (struct syscall_monitor_point_struct *)kmem_cache_alloc(syscall_monitor_point_cachep, GFP_KERNEL);
	if(!point)
	{
		send_msg.errno = RET_NO_MEMORY;
		goto err;
	}

	memset(point, 0, sizeof(struct syscall_monitor_point_struct));
	point->object.type = recv_msg->object.type;
	point->syscallno = recv_msg->syscallno;
	switch(recv_msg->object.type)
	{
		case TYPE_PID:
			point->object.pid = recv_msg->object.pid;
			DEBUG_PRINT(LEVEL_INFO, "add rule: syscallname = %s, pid = %ld, timeout = %luns\n", syscall_nr_to_meta(recv_msg->syscallno), recv_msg->object.pid, recv_msg->timeout);
			break;
		case TYPE_TGID:
			point->object.tgid = recv_msg->object.tgid;
			DEBUG_PRINT(LEVEL_INFO, "add rule: syscallname = %s, tgid = %ld, timeout = %luns\n", syscall_nr_to_meta(recv_msg->syscallno), recv_msg->object.tgid, recv_msg->timeout);
			break;
		case TYPE_COMM:
			sprintf(point->object.comm, "%s", recv_msg->object.comm);
			DEBUG_PRINT(LEVEL_INFO, "add rule: syscallname = %s, comm = %s, timeout = %luns\n", syscall_nr_to_meta(recv_msg->syscallno), recv_msg->object.comm, recv_msg->timeout);
			break;
		case TYPE_ALL:
			send_msg.errno = RET_INVAILD_TYPE;
			break;
		default:
			BUG();
	}
	point->timeout = recv_msg->timeout;
	spin_lock_init(&point->timer_lock);
	INIT_LIST_HEAD(&point->timer_list);
	list_add_rcu(&point->syscall_list, syscall_monitor_point_head + recv_msg->syscallno);
	atomic_inc(syscall_monitor_count + recv_msg->syscallno);
	send_msg.errno = RET_SUCCESS;
err:
	return syscall_monitor_skb(nlh->nlmsg_seq, &send_msg, sizeof(struct syscall_monitor_send_msg_struct));
}

static struct sk_buff *syscall_monitor_delete(struct nlmsghdr *nlh)
{
	struct syscall_monitor_recv_msg_struct *recv_msg;
	struct syscall_monitor_point_struct *point;
	struct syscall_monitor_send_msg_struct send_msg;
	struct syscall_monitor_timer_struct *timer, *tnext;

	send_msg.ops = OPS_DELETE;
	send_msg.retnum = 0;
	recv_msg = (struct syscall_monitor_recv_msg_struct *)nlmsg_data(nlh);

	rcu_read_lock();
	point = syscall_monitor_find_rcu(recv_msg->syscallno, &recv_msg->object);
	if(!point)
	{
		rcu_read_unlock();
		send_msg.errno = RET_NOT_FOUND;
		goto err;
	}
	rcu_read_unlock();

	if(atomic_read(syscall_monitor_count + recv_msg->syscallno) == 0)
		BUG();
	list_del_rcu(&point->syscall_list);
	switch(point->object.type)
	{
		case TYPE_PID:
			DEBUG_PRINT(LEVEL_INFO, "delete rule: syscallname = %s, pid = %ld, timeout = %luns\n", syscall_nr_to_meta(point->syscallno), point->object.pid, point->timeout);
			break;
		case TYPE_TGID:
			DEBUG_PRINT(LEVEL_INFO, "delete rule: syscallname = %s, tgid = %ld, timeout = %luns\n", syscall_nr_to_meta(point->syscallno), point->object.tgid, point->timeout);
			break;
		case TYPE_COMM:
			DEBUG_PRINT(LEVEL_INFO, "delete rule: syscallname = %s, comm = %s, timeout = %luns\n", syscall_nr_to_meta(point->syscallno), point->object.comm, point->timeout);
			break;
		default:
			DEBUG_PRINT(LEVEL_WARNING, "delete rule? what");
	}

	atomic_dec(syscall_monitor_count + recv_msg->syscallno);

	spin_lock(&point->timer_lock);
	list_for_each_entry_safe(timer, tnext, &point->timer_list, list)
	{
		hrtimer_cancel(&timer->timer);
		list_del(&timer->list);
		kmem_cache_free(syscall_monitor_timer_cachep, timer);
	}
	spin_unlock(&point->timer_lock);
	kmem_cache_free(syscall_monitor_point_cachep, point);

	send_msg.errno = RET_SUCCESS;
err:
	return syscall_monitor_skb(nlh->nlmsg_seq, &send_msg, sizeof(struct syscall_monitor_send_msg_struct));
}

static struct sk_buff *syscall_monitor_modify(struct nlmsghdr *nlh)
{
	struct syscall_monitor_recv_msg_struct *recv_msg;
	struct syscall_monitor_point_struct *point, *npoint;
	struct syscall_monitor_send_msg_struct send_msg;
	struct syscall_monitor_timer_struct *timer, *tnext;

	send_msg.ops = OPS_MODFIY;
	send_msg.retnum = 0;
	recv_msg = (struct syscall_monitor_recv_msg_struct *)nlmsg_data(nlh);

	rcu_read_lock();
	point = syscall_monitor_find_rcu(recv_msg->syscallno, &recv_msg->object);
	if(!point)
	{
		rcu_read_unlock();
		send_msg.errno = RET_NOT_FOUND;
		goto err;
	}
	rcu_read_unlock();

	npoint = (struct syscall_monitor_point_struct *)kmem_cache_alloc(syscall_monitor_point_cachep, GFP_KERNEL);
	if(!npoint)
	{
		send_msg.errno = RET_NO_MEMORY;
		goto err;
	}

	memset(npoint, 0, sizeof(struct syscall_monitor_point_struct));
	npoint->object.type = recv_msg->object.type;
	npoint->syscallno = recv_msg->syscallno;
	switch(recv_msg->object.type)
	{
		case TYPE_PID:
			npoint->object.pid = recv_msg->object.pid;
			break;
		case TYPE_TGID:
			npoint->object.tgid = recv_msg->object.tgid;
			break;
		case TYPE_COMM:
			sprintf(npoint->object.comm, "%s", recv_msg->object.comm);
			break;
		case TYPE_ALL:
			send_msg.errno = RET_INVAILD_TYPE;
			break;
		default:
			BUG();
	}
	npoint->timeout = recv_msg->timeout;
	spin_lock_init(&npoint->timer_lock);
	INIT_LIST_HEAD(&npoint->timer_list);

	list_replace_rcu(&point->syscall_list, &npoint->syscall_list);

	switch(recv_msg->object.type)
	{
		case TYPE_PID:
			DEBUG_PRINT(LEVEL_INFO, "modify rule: syscallname = %s, pid = %ld, oldtimeout = %luns, newtimeout = %luns\n", syscall_nr_to_meta(point->syscallno), point->object.pid, point->timeout, npoint->timeout);
			break;
		case TYPE_TGID:
			DEBUG_PRINT(LEVEL_INFO, "modify rule: syscallname = %s, tgid = %ld, oldtimeout = %luns, newtimeout = %luns\n", syscall_nr_to_meta(point->syscallno), point->object.tgid, point->timeout, npoint->timeout);
			break;
		case TYPE_COMM:
			DEBUG_PRINT(LEVEL_INFO, "modify rule: syscallname = %s, comm = %s, oldtimeout = %luns, newtimeout = %luns\n", syscall_nr_to_meta(point->syscallno), point->object.comm, point->timeout, npoint->timeout);
			break;
		default:
			DEBUG_PRINT(LEVEL_WARNING, "modify rule? what");
	}	

	spin_lock(&point->timer_lock);
	list_for_each_entry_safe(timer, tnext, &point->timer_list, list)
	{
		hrtimer_cancel(&timer->timer);
		list_del(&timer->list);
		kmem_cache_free(syscall_monitor_timer_cachep, timer);
	}
	spin_unlock(&point->timer_lock);
	kmem_cache_free(syscall_monitor_point_cachep, point);
	send_msg.errno = RET_SUCCESS;
err:
	return syscall_monitor_skb(nlh->nlmsg_seq, &send_msg, sizeof(struct syscall_monitor_send_msg_struct));

}

static struct sk_buff *syscall_monitor_find(struct nlmsghdr *nlh)
{
	struct syscall_monitor_recv_msg_struct *recv_msg;
	struct syscall_monitor_point_struct *point;
	struct syscall_monitor_send_msg_struct send_msg;
	struct syscall_monitor_send_msg_struct *nsend_msg;
	struct syscall_monitor_send_ret_struct *send_ret;
	struct sk_buff *skb;

	send_msg.ops = OPS_FIND;
	send_msg.retnum = 0;
	recv_msg = (struct syscall_monitor_recv_msg_struct *)nlmsg_data(nlh);

	rcu_read_lock();
	if(recv_msg->object.type == TYPE_ALL)
	{
		nsend_msg = (struct syscall_monitor_send_msg_struct *)vmalloc(sizeof(struct syscall_monitor_send_msg_struct) + sizeof(struct syscall_monitor_send_ret_struct) * (atomic_read(syscall_monitor_count + recv_msg->syscallno) + num_present_cpus()));

		if(nsend_msg == NULL)
		{
			send_msg.errno = RET_NO_MEMORY;
			goto err;
		}

		send_ret = (struct syscall_monitor_send_ret_struct *)(nsend_msg + 1);
		nsend_msg->ops = OPS_FIND;
		nsend_msg->retnum = 0;
		list_for_each_entry_rcu(point, &syscall_monitor_point_head[recv_msg->syscallno], syscall_list)
		{
			send_ret->syscallno = recv_msg->syscallno;
			memcpy(&send_ret->object, &point->object, sizeof(struct syscall_monitor_object_struct));
			send_ret->timeout = point->timeout;
			send_ret++;
			nsend_msg->retnum++;
		}
		rcu_read_unlock();
		nsend_msg->errno = RET_SUCCESS;
		goto out;
	}

	point = syscall_monitor_find_rcu(recv_msg->syscallno, &recv_msg->object);
	if(point == NULL)
	{
		rcu_read_unlock();
		send_msg.errno = RET_NOT_FOUND;
		goto err;
	}
	
	nsend_msg = (struct syscall_monitor_send_msg_struct *)vmalloc(sizeof(struct syscall_monitor_send_msg_struct) + sizeof(struct syscall_monitor_send_ret_struct));
	if(nsend_msg == NULL)
	{       
		send_msg.errno = RET_NO_MEMORY;
		goto err;
	}

	send_ret = (struct syscall_monitor_send_ret_struct *)(nsend_msg + 1);
	send_ret->syscallno = recv_msg->syscallno;
	memcpy(&send_ret->object, &point->object, sizeof(struct syscall_monitor_object_struct));
	send_ret->timeout = point->timeout;
	nsend_msg->ops = OPS_FIND;
	nsend_msg->retnum = 1;
	nsend_msg->errno = RET_SUCCESS;
	rcu_read_unlock();
out:
	switch(recv_msg->object.type)
	{
		case TYPE_PID:
			DEBUG_PRINT(LEVEL_INFO, "find rule: syscallname = %s, pid = %ld, retnum = %d\n", syscall_nr_to_meta(recv_msg->syscallno), send_ret->object.pid, nsend_msg->retnum);
			break;
		case TYPE_TGID:
			DEBUG_PRINT(LEVEL_INFO, "find rule: syscallname = %s, tgid = %ld, retnum = %d\n", syscall_nr_to_meta(recv_msg->syscallno), send_ret->object.tgid, nsend_msg->retnum);
			break;
		case TYPE_COMM:
			DEBUG_PRINT(LEVEL_INFO, "find rule: syscallname = %s, comm = %s, retnum = %d\n", syscall_nr_to_meta(recv_msg->syscallno), send_ret->object.comm, nsend_msg->retnum);
			break;
		case TYPE_ALL:
			DEBUG_PRINT(LEVEL_INFO, "find rule: syscallname = %s, all, retnum = %d\n", syscall_nr_to_meta(recv_msg->syscallno), nsend_msg->retnum);
			break;
		default:
			DEBUG_PRINT(LEVEL_WARNING, "find rule? what");
	}

	skb = syscall_monitor_skb(nlh->nlmsg_seq, nsend_msg, sizeof(struct syscall_monitor_send_msg_struct) + nsend_msg->retnum * sizeof(struct syscall_monitor_send_ret_struct));
	vfree(nsend_msg);
	return skb;
err:
	return syscall_monitor_skb(nlh->nlmsg_seq, &send_msg, sizeof(struct syscall_monitor_send_msg_struct));	
}

//进口校验用户态数据
static int syscall_monitor_rcv_msg(struct sk_buff *skb, struct nlmsghdr *nlh, struct netlink_ext_ack *extack)
{
	struct syscall_monitor_recv_msg_struct *recv_msg;
	struct sk_buff *nskb;
	struct syscall_monitor_send_msg_struct send_msg;

	send_msg.retnum = 0;
	if (nlmsg_len(nlh) < sizeof(struct syscall_monitor_recv_msg_struct))
	{
		send_msg.ops = OPS_UNKNOWN;
		send_msg.errno = RET_ERROR_MSG;
		goto err;
	}

	recv_msg = (struct syscall_monitor_recv_msg_struct *)nlmsg_data(nlh);
	recv_msg->object.comm[TASK_COMM_LEN - 1] = 0;

	send_msg.ops = recv_msg->ops;
	if(recv_msg->object.type >= TYPE_MAX)
	{
		send_msg.errno = RET_INVAILD_TYPE;
		goto err;
	}
	if(recv_msg->syscallno >= NR_syscalls || recv_msg->syscallno == __NR_exit)
	{
		send_msg.errno = RET_INVAILD_SYSCALL;
		goto err;
	}

	//以下操作只能在netlink大锁中执行，rcu同时执行会导致内存泄露或者内存panic
	switch(recv_msg->ops)
	{
		case OPS_ADD:
			nskb = syscall_monitor_add(nlh);
			break;
		case OPS_DELETE:
			nskb = syscall_monitor_delete(nlh);
			break;
		case OPS_MODFIY:
			nskb = syscall_monitor_modify(nlh);
			break;
		case OPS_FIND:
			nskb = syscall_monitor_find(nlh);
			break;
		default:
			send_msg.errno = RET_INVAILD_OPS;
			goto err;
	}
	goto out;

err:
	nskb = syscall_monitor_skb(nlh->nlmsg_seq, &send_msg, sizeof(struct syscall_monitor_send_msg_struct));
	if(!nskb)
		return 0;	
out:
	netlink_unicast(syscall_monitor_sk, nskb, nlh->nlmsg_pid, MSG_DONTWAIT);
	return 0;
}

static void syscall_monitor_rcv(struct sk_buff *skb)
{
	mutex_lock(&syscall_monitor_mutex);
	netlink_rcv_skb(skb, &syscall_monitor_rcv_msg);
	mutex_unlock(&syscall_monitor_mutex);
}

static enum hrtimer_restart syscall_monitor_timer_fn(struct hrtimer *hrtimer)
{
	struct syscall_monitor_timer_struct *timer;
	struct syscall_monitor_record_struct *record;
	unsigned long *entries;
	int syscallno;

	timer = container_of(hrtimer, struct syscall_monitor_timer_struct, timer);
	hrtimer_forward_now(hrtimer, ns_to_ktime(timer->point->timeout));

	syscallno = timer->point->syscallno;
	record = kmem_cache_alloc(syscall_monitor_record_cachep, GFP_ATOMIC);
	if(record == NULL)
		return HRTIMER_RESTART;

	entries = kmalloc_array(MAX_STACK_SYSMON_DEPTH, sizeof(*entries), GFP_ATOMIC);
	if(entries == NULL)
	{
		kmem_cache_free(syscall_monitor_record_cachep, record);
		return HRTIMER_RESTART;
	}

	getnstimeofday(&record->catch_time);
	memcpy(&record->start_time, &timer->start_time, sizeof(struct timespec));

	record->cpu = timer->cpu;
	record->state = timer->task->state;
	record->ppid = timer->task->parent->pid;
	record->tgid = timer->task->tgid;
	record->pid = timer->task->pid;
	sprintf(record->pcomm, "%s", timer->task->parent->comm);
	sprintf(record->tcomm, "%s", pid_task(find_vpid(timer->task->tgid), PIDTYPE_PID)->comm);
	sprintf(record->comm, "%s", timer->task->comm);

	record->trace.nr_entries        = 0;
	record->trace.max_entries       = MAX_STACK_SYSMON_DEPTH;
	record->trace.entries           = entries;
	record->trace.skip              = 0;

	//要上锁吗？
	save_stack_trace_tsk(timer->task, &record->trace);

	spin_lock(syscall_monitor_record_lock + syscallno);
	list_add_tail(&record->list, syscall_monitor_record_head + syscallno);
	syscall_monitor_current_record_count[syscallno] ++;
	if(syscall_monitor_current_record_count[syscallno] >= syscall_monitor_flush_record_count)
		wake_up_process(syscall_monitor_task);
	spin_unlock(syscall_monitor_record_lock + syscallno);

	return HRTIMER_RESTART;
}

static void syscall_monitor_syscall_enter(void *ignore, struct pt_regs *regs, long id)
{
	struct syscall_monitor_point_struct *point;
	struct syscall_monitor_object_struct object;
	struct syscall_monitor_timer_struct *timer;
	int syscall_nr;

	syscall_nr = syscall_get_nr(current, regs);
	if (syscall_nr < 0 || syscall_nr >= NR_syscalls || syscall_nr == __NR_exit)
		return;

	rcu_read_lock();

	object.type = TYPE_PID;
	object.pid = current->pid;
	point = syscall_monitor_find_rcu(syscall_nr, &object);
	if(point != NULL)
		goto find;

	object.type = TYPE_TGID;
	object.tgid = current->tgid;
	point = syscall_monitor_find_rcu(syscall_nr, &object);
	if(point != NULL)
		goto find;

	object.type = TYPE_COMM;
	sprintf(object.comm, "%s", current->comm);
	point = syscall_monitor_find_rcu(syscall_nr, &object);
	if(point != NULL)
		goto find;

	rcu_read_unlock();
	return;
find:
	timer = (struct syscall_monitor_timer_struct *)kmem_cache_alloc(syscall_monitor_timer_cachep, GFP_KERNEL);
	if(timer == NULL)
		return;

	timer->task = current;
	timer->point = point;
	timer->cpu = smp_processor_id();
	getnstimeofday(&timer->start_time);
	hrtimer_init(&timer->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	timer->timer.function = syscall_monitor_timer_fn;
	hrtimer_start(&timer->timer, ns_to_ktime(point->timeout), HRTIMER_MODE_REL_PINNED);

	spin_lock(&point->timer_lock);
	list_add(&timer->list, &point->timer_list);
	spin_unlock(&point->timer_lock);

	rcu_read_unlock();
}

static void syscall_monitor_syscall_exit(void *ignore, struct pt_regs *regs, long ret)
{
	struct syscall_monitor_point_struct *point;
	struct syscall_monitor_object_struct object;
	struct syscall_monitor_timer_struct *timer, *tnext;
	int syscall_nr;
	int notfind;

	notfind = 0;
	syscall_nr = syscall_get_nr(current, regs);
	if (syscall_nr < 0 || syscall_nr >= NR_syscalls || syscall_nr == __NR_exit)
		return;

	rcu_read_lock();

	object.type = TYPE_PID;
	object.pid = current->pid;
	point = syscall_monitor_find_rcu(syscall_nr, &object);
	if(point != NULL)
		goto find;
	notfind ++;

retry_tgid:
	object.type = TYPE_TGID;
	object.tgid = current->tgid;
	point = syscall_monitor_find_rcu(syscall_nr, &object);
	if(point != NULL)
		goto find;

	notfind ++;

retry_comm:
	object.type = TYPE_COMM;
	sprintf(object.comm, "%s", current->comm);
	point = syscall_monitor_find_rcu(syscall_nr, &object);
	if(point != NULL)
		goto find;

	notfind ++;

	goto out;
find:
	spin_lock(&point->timer_lock);
	list_for_each_entry_safe(timer, tnext, &point->timer_list, list)
	{
		if(current->pid == timer->task->pid)
		{
			hrtimer_cancel(&timer->timer);
			list_del(&timer->list);
			kmem_cache_free(syscall_monitor_timer_cachep, timer);
			spin_unlock(&point->timer_lock);
			goto out;
		}
	}
	spin_unlock(&point->timer_lock);
	notfind ++;
	if(notfind == 1)
		goto retry_tgid;
	if(notfind == 2)
		goto retry_comm;
out:
	rcu_read_unlock();
}

static int syscall_monitor_record_thread(void *unused)
{
	int i;
	int syscallno;
	unsigned long *entries;
	struct list_head head;
	struct sk_buff *skb;
	struct syscall_monitor_record_struct *record, *rnext;
	struct syscall_monitor_send_msg_struct *send_msg;
	struct syscall_monitor_send_record_struct *send_record;

	while (!kthread_should_stop())
	{
		send_msg = NULL;
		send_record = NULL;
		if(send_msg == NULL)
		{
			send_msg = (struct syscall_monitor_send_msg_struct *)vmalloc(sizeof(struct syscall_monitor_send_msg_struct) + sizeof(struct syscall_monitor_send_record_struct));
			if(send_msg == NULL)
			{
				DEBUG_PRINT(LEVEL_WARNING, "Cannot allocate send_msg memory\n");
				goto schedule;
			}
			send_record = (struct syscall_monitor_send_record_struct *)(send_msg + 1);
		}

		for(syscallno = 0; syscallno < NR_syscalls; syscallno++)
		{
			spin_lock(syscall_monitor_record_lock + syscallno);
			if(list_empty(syscall_monitor_record_head + syscallno))
			{
				spin_unlock(syscall_monitor_record_lock + syscallno);
				continue;
			}

			INIT_LIST_HEAD( &head);
			list_splice_init(syscall_monitor_record_head + syscallno ,&head);
			syscall_monitor_current_record_count[syscallno] = 0;
			spin_unlock(syscall_monitor_record_lock + syscallno);

			send_msg->ops = OPS_RECORD;
			send_msg->errno = RET_SUCCESS;
			send_msg->retnum = 1;
			list_for_each_entry_safe(record, rnext, &head, list)
			{
				memset(send_record, 0, sizeof(struct syscall_monitor_send_record_struct));
				send_record->syscallno = syscallno;
				send_record->cpu = record->cpu;
				send_record->state = record->state;
				send_record->ppid = record->ppid;
				send_record->tgid = record->tgid;
				send_record->pid = record->pid;
				sprintf(send_record->pcomm, "%s", record->pcomm);
				sprintf(send_record->tcomm, "%s", record->tcomm);
				sprintf(send_record->comm, "%s", record->comm);
				memcpy(&send_record->start_time, &record->start_time, sizeof(struct timespec));
				memcpy(&send_record->catch_time, &record->catch_time, sizeof(struct timespec));
				entries = record->trace.entries;
				for (i = 0; i < record->trace.nr_entries; i++) 
					sprintf(send_record->stack, "%s[<0>] %pB\n", send_record->stack, (void *)entries[i]);
				skb = syscall_monitor_skb(0, send_msg, sizeof(struct syscall_monitor_send_msg_struct) + sizeof(struct syscall_monitor_send_record_struct));
				DEBUG_PRINT(LEVEL_DEBUG, "syscallname = %s, cpu = %d, state = %s, pcomm = %s(%d), tcomm = %s(%d), comm = %s(%d), stime = %lu.%lu, ctime = %lu.%lu\n", syscall_nr_to_meta(send_record->syscallno), send_record->cpu, trans_task_state(send_record->state), send_record->pcomm, send_record->ppid, send_record->tcomm, send_record->tgid, send_record->comm, send_record->pid, send_record->start_time.tv_sec, send_record->start_time.tv_nsec, send_record->catch_time.tv_sec - send_record->start_time.tv_sec, send_record->catch_time.tv_nsec - send_record->start_time.tv_nsec);
				DEBUG_PRINT(LEVEL_DEBUG, "stack");
				DEBUG_PRINT(LEVEL_DEBUG, "%s\n", send_record->stack);
				if(skb != NULL)
				{
					NETLINK_CB(skb).portid = 0;
					NETLINK_CB(skb).dst_group = 1;
					netlink_broadcast(syscall_monitor_sk, skb, 0, 1, GFP_KERNEL);
				}

				list_del(&record->list);
				kfree(record->trace.entries);
				kmem_cache_free(syscall_monitor_record_cachep, record);
			}
		}
schedule:
		schedule_timeout_interruptible(syscall_monitor_sleep_second * HZ); 
	}
	return 0;
}

static int __init syscall_monitor_init(void)
{
	int err;
	int syscallno;
	unsigned long *addr;
	struct netlink_kernel_cfg cfg = {
		.groups         = 1,
		.input          = syscall_monitor_rcv,
	};
	syscall_monitor_point_cachep = kmem_cache_create("syscall_monitor_point", sizeof(struct syscall_monitor_point_struct), 0, 0, NULL);
	if(!syscall_monitor_point_cachep)
	{	
		err = -ENOMEM;
		goto err_syscall_monitor_point_cachep;
	}

	syscall_monitor_timer_cachep = kmem_cache_create("syscall_monitor_timer", sizeof(struct syscall_monitor_timer_struct), 0, 0, NULL);
	if(!syscall_monitor_timer_cachep)
	{	
		err = -ENOMEM;
		goto err_syscall_monitor_timer_cachep;
	}

	syscall_monitor_record_cachep = kmem_cache_create("syscall_monitor_record", sizeof(struct syscall_monitor_record_struct), 0, 0, NULL);
	if(syscall_monitor_record_cachep == NULL)
	{
		err = -ENOMEM;
		goto err_syscall_monitor_record_cachep;
	}

	for(syscallno = 0; syscallno < NR_syscalls; syscallno++)
	{
		INIT_LIST_HEAD(syscall_monitor_point_head + syscallno);
		atomic_set(syscall_monitor_count + syscallno, 0);
		INIT_LIST_HEAD(syscall_monitor_record_head + syscallno);
		syscall_monitor_current_record_count[syscallno] = 0;
		spin_lock_init(syscall_monitor_record_lock + syscallno);
	}

	//注册回调
	err = register_trace_probe("sys_enter", syscall_monitor_syscall_enter, NULL);
	if(err != 0)
		goto err_register_trace_probe_sys_enter;

	err = register_trace_probe("sys_exit", syscall_monitor_syscall_exit, NULL);
	if(err != 0)
		goto err_register_trace_probe_sys_exit;

	syscall_monitor_sk = netlink_kernel_create(&init_net, NETLINK_SYSMON, &cfg);
	if (!syscall_monitor_sk)
	{
		err = -ENOMEM;
		goto err_syscall_monitor_sk;
	}

	syscall_monitor_task = kthread_run(syscall_monitor_record_thread, NULL, "syscall_monitor");
	if (IS_ERR(syscall_monitor_task))
	{
		err = -ENOMEM;
		goto err_syscall_monitor_task;
	}

	syscall_monitor_table_head = register_sysctl("syscall_monitor", syscall_monitor_table);
	if(syscall_monitor_table_head == NULL)
	{
		err = -ENOMEM;
		goto err_syscall_monitor_table_head;
	}

	addr = (unsigned long *)kallsyms_lookup_name("syscalls_metadata");
	if(addr == NULL)
	{
		err = -ENOMEM;
		goto err_fsyscalls_metadata;
	}
	fsyscalls_metadata = (struct syscall_metadata **)*addr;
	return 0;
err_fsyscalls_metadata:
	unregister_sysctl_table(syscall_monitor_table_head);
err_syscall_monitor_table_head:
	kthread_stop(syscall_monitor_task);
err_syscall_monitor_task:
	netlink_kernel_release(syscall_monitor_sk);
err_syscall_monitor_sk:
	unregister_trace_probe("sys_exit", syscall_monitor_syscall_enter, NULL);
err_register_trace_probe_sys_exit:
	unregister_trace_probe("sys_enter", syscall_monitor_syscall_enter, NULL);
err_register_trace_probe_sys_enter:
	kmem_cache_destroy(syscall_monitor_record_cachep);
err_syscall_monitor_record_cachep:
	kmem_cache_destroy(syscall_monitor_timer_cachep);
err_syscall_monitor_timer_cachep:
	kmem_cache_destroy(syscall_monitor_point_cachep);
err_syscall_monitor_point_cachep:
	return err;

}

static void __exit syscall_monitor_exit(void)
{
	int syscallno;
	struct syscall_monitor_point_struct *point, *pnext;
	struct syscall_monitor_timer_struct *timer, *tnext;
	struct syscall_monitor_record_struct *record, *rnext;

	unregister_sysctl_table(syscall_monitor_table_head);
	kthread_stop(syscall_monitor_task);
	netlink_kernel_release(syscall_monitor_sk);
	syscall_monitor_sk = NULL;
	//卸载回调
	unregister_trace_probe("sys_enter", syscall_monitor_syscall_enter, NULL);
	unregister_trace_probe("sys_exit", syscall_monitor_syscall_exit, NULL);
	//回收slab
	for(syscallno = 0; syscallno < NR_syscalls; syscallno++)
	{
		list_for_each_entry_safe(point, pnext, syscall_monitor_point_head + syscallno, syscall_list)
		{
			list_del_rcu(&point->syscall_list);
			spin_lock(&point->timer_lock);
			list_for_each_entry_safe(timer, tnext, &point->timer_list, list)
			{
				list_del(&timer->list);
				hrtimer_cancel(&timer->timer);
				kmem_cache_free(syscall_monitor_timer_cachep, timer);
			}
			spin_unlock(&point->timer_lock);
			kmem_cache_free(syscall_monitor_point_cachep, point);
		}
		atomic_set(syscall_monitor_count + syscallno, 0);

		spin_lock(syscall_monitor_record_lock + syscallno);
		list_for_each_entry_safe(record, rnext, syscall_monitor_record_head + syscallno, list)
		{
			list_del(&record->list);
			kfree(record->trace.entries);
			kmem_cache_free(syscall_monitor_record_cachep, record);
		}
		spin_unlock(syscall_monitor_record_lock + syscallno);
	}

	kmem_cache_destroy(syscall_monitor_record_cachep);
	syscall_monitor_timer_cachep = NULL;
	kmem_cache_destroy(syscall_monitor_timer_cachep);
	syscall_monitor_timer_cachep = NULL;
	kmem_cache_destroy(syscall_monitor_point_cachep);
	syscall_monitor_point_cachep = NULL;
}
module_init(syscall_monitor_init);
module_exit(syscall_monitor_exit);
MODULE_LICENSE("GPL");
MODULE_VERSION("v1.0.0");
MODULE_DESCRIPTION("syscall monitor");
MODULE_AUTHOR("Wang Qiang, wang1131695576@outlook.com");
