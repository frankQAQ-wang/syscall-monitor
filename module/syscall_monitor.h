#ifndef __SYSCALL_MONITOR_H
#define __SYSCALL_MONITOR_H

#include <linux/hrtimer.h>
#include <linux/spinlock.h>
#include <linux/stacktrace.h>

extern struct net init_net;
#define MAX_STACK_MSG   624
enum syscall_monitor_point_ops
{
	OPS_ADD = 1,
	OPS_DELETE,
	OPS_MODFIY,
	OPS_FIND,
	OPS_RECORD,
	OPS_UNKNOWN,
};

enum syscall_monitor_point_type
{
	TYPE_PID = 1,
	TYPE_TGID,
	TYPE_COMM,
	TYPE_ALL,
	TYPE_MAX
};

enum syscall_monitor_ret_type
{
	RET_SUCCESS = 1,
	RET_CONFLICT,
	RET_NOT_FOUND,
	RET_NO_MEMORY,
	RET_INVAILD_OPS,
	RET_INVAILD_TYPE,
	RET_OVER_COUNT,
	RET_ERROR_MSG,
	RET_INVAILD_SYSCALL,
};

struct syscall_monitor_record_struct
{
	int cpu;
	int state;
	pid_t ppid;
	pid_t tgid;
	pid_t pid;
	char pcomm[TASK_COMM_LEN];
	char tcomm[TASK_COMM_LEN];
	char comm[TASK_COMM_LEN];
	int curr_state;
	pid_t curr_pid;
	int curr_prio;
	unsigned int curr_policy;
	char curr_comm[TASK_COMM_LEN];
	unsigned long curr_durtime;
	struct timespec start_time;
	struct timespec catch_time;
	struct stack_trace trace;
	struct list_head list;
};

struct syscall_monitor_object_struct
{

	enum syscall_monitor_point_type type;
	union   
	{       
		unsigned long pid;
		unsigned long tgid;
		char comm[TASK_COMM_LEN];
	};
};

struct syscall_monitor_point_struct
{
	struct syscall_monitor_object_struct object;
	unsigned long timeout;
	unsigned int syscallno;
	spinlock_t timer_lock;
	struct list_head timer_list;
	struct list_head syscall_list;
};

struct syscall_monitor_timer_struct
{
	struct task_struct *task;
	int cpu;
	struct timespec start_time;
	struct hrtimer timer;
	struct syscall_monitor_point_struct *point;
	struct list_head list;
};

struct syscall_monitor_recv_msg_struct
{
	enum syscall_monitor_point_ops ops;
	struct syscall_monitor_object_struct object;
	unsigned int syscallno;
	unsigned long timeout;
};

struct syscall_monitor_send_msg_struct
{
	enum syscall_monitor_point_ops ops;
	int errno;
	int retnum;
};

struct syscall_monitor_send_ret_struct
{
	unsigned int syscallno;
	struct syscall_monitor_object_struct object;
	unsigned long timeout;
};

struct syscall_monitor_send_record_struct
{
	int syscallno;
	int cpu;
	int state;
	pid_t ppid;
	pid_t tgid;
	pid_t pid;
	char pcomm[TASK_COMM_LEN];
	char tcomm[TASK_COMM_LEN];
	char comm[TASK_COMM_LEN];
	int curr_state;
	pid_t curr_pid;
	int curr_prio;
	unsigned int curr_policy;
	char curr_comm[TASK_COMM_LEN];
	unsigned long curr_durtime;
	struct timespec start_time;
	struct timespec catch_time;
	char stack[MAX_STACK_MSG];
};
#endif
