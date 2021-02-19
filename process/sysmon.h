#ifndef __SYSMON_H
#define __SYSMON_H

#define SOCKET_PATH	"/run/sysmon/"
#define SOCKET_NAME	"common"
#define TASK_COMM_LEN   16
#define MAX_STACK_MSG	624

enum sysmon_pops
{
	OPS_ADD = 1,
	OPS_DELETE,
	OPS_MODIFY,
	OPS_FIND,
	OPS_RECORD,
	OPS_UNKNOWN,
};

enum sysmon_ptype
{
	TYPE_PID = 1,
	TYPE_TGID,
	TYPE_COMM,
	TYPE_TGCOMM,
	TYPE_PPID,
	TYPE_PCOMM,
	TYPE_ALL,
	TYPE_MAX
};

enum sysmon_rtype
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

struct sysmon_obj_struct
{

	enum sysmon_ptype type;
	union
	{
		unsigned long pid;
		unsigned long tgid;
		char comm[TASK_COMM_LEN];
		char tgcomm[TASK_COMM_LEN];
		unsigned long ppid;
		char pcomm[TASK_COMM_LEN];
	};
};

struct sysmon_rmsg_struct
{
	enum sysmon_pops ops;
	struct sysmon_obj_struct obj;
	unsigned int sysno;
	unsigned long timeout;
};

struct sysmon_smsg_struct
{
	enum sysmon_pops ops;
	int errnu;
	int retnum;
};

struct sysmon_sret_struct
{
	unsigned int sysno;
	struct sysmon_obj_struct obj;
	unsigned long timeout;
};

struct sysmon_srecord_struct
{
	int sysno;
	int cpu;
	int state;
	int ppid;
	int tgid;
	int pid;
	char pcomm[TASK_COMM_LEN];
	char tcomm[TASK_COMM_LEN];
	char comm[TASK_COMM_LEN];
	int curr_state;
	pid_t curr_pid;
	int curr_prio;
	unsigned int curr_policy;
	char curr_comm[TASK_COMM_LEN];
	unsigned long curr_durtime;
	struct timespec stime;
	struct timespec ctime;
	char stack[MAX_STACK_MSG];
};

#endif
