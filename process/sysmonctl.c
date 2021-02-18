#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdlib.h>

#define _S(syscallno, name) name,
static char *syscallarray[] = {
#include "syscall_table.h"
	NULL
};

#include "sysmon.h"

#define MAX_LEN (8 * 1024 *1024)
int syscall_name2no(char *name)
{
	int no;
	char **p;

	p = syscallarray;
	for(no = 0; syscallarray[no] != NULL; no++)
		if(strcmp(syscallarray[no], name) == 0)
			return no;
	return -1;
}

int parse_arg(struct sysmon_rmsg_struct *rmsg, int argc, char *argv[])
{
	int syscallno, len;
	long timeout;

	if(strcmp(argv[0], "syscall") == 0)
	{
		syscallno = syscall_name2no(argv[1]);
		if(syscallno == -1)
		{
			printf("invaild arguments: %s\n", argv[1]);
			return -1;
		}

		rmsg->sysno = syscallno;
	}
	else
	{
		printf("invaild arguments: %s\n", argv[0]);
		return -1;
	}

	if(argc == 2)
		return 0;

	if(strcmp(argv[2], "pid") == 0)
	{
		rmsg->obj.type = TYPE_PID;
		rmsg->obj.pid = atoi(argv[3]);
	}
	else if(strcmp(argv[2], "tgid") == 0)
	{
		rmsg->obj.type = TYPE_TGID;
		rmsg->obj.tgid = atoi(argv[3]);
	}
	else if(strcmp(argv[2], "comm") == 0)
	{
		rmsg->obj.type = TYPE_COMM;
		sprintf(rmsg->obj.comm, "%s", argv[3]);
	}
	else if(strcmp(argv[2], "all") == 0)
	{
		rmsg->obj.type = TYPE_ALL;
	}
	else
	{
		printf("invaild arguments: %s\n", argv[3]);
		return -1;
	}

	if(argc == 4)
		return 0;

	if(strcmp(argv[4], "timeout") == 0)
	{
		len = strlen(argv[5]);
		if(len < 1)
		{
			printf("invaild arguments: %s\n", argv[5]);
			return -1;
		}

		if(argv[5][len - 1] == 's' && argv[5][len - 2] == 'n')
		{
			argv[5][len - 2] == 0;
			timeout = atol(argv[5]);
		}
		else if(argv[5][len - 1] == 's' && argv[5][len - 2] == 'u')
		{
			argv[5][len - 2] == 0;
			timeout = atol(argv[5]) * 1000;
		}
		else if(argv[5][len - 1] == 's' && argv[5][len - 2] == 'u')
		{
			argv[5][len - 2] == 0;
			timeout = atol(argv[5]) * 1000 * 1000;
		}
		else
		{
			argv[5][len - 1] == 0;
			timeout = atol(argv[5]) * 1000 * 1000 * 1000;
		}
		rmsg->timeout = timeout;
	}

	return 0;
}

int sysmonctl_add(struct sysmon_rmsg_struct *rmsg, int argc, char *argv[])
{
	if(argc < 6)
	{
		printf("not enough arguments\n");
		return -1;
	}

	rmsg->ops = OPS_ADD;
	return parse_arg(rmsg, argc, argv);
}

int sysmonctl_delete(struct sysmon_rmsg_struct *rmsg, int argc, char *argv[])
{
	if(argc < 4)
	{
		printf("not enough arguments\n");
		return -1;
	}

	rmsg->ops = OPS_DELETE;
	return parse_arg(rmsg, argc, argv);
}

int sysmonctl_modify(struct sysmon_rmsg_struct *rmsg, int argc, char *argv[])
{
	if(argc < 6)
	{
		printf("not enough arguments\n");
		return -1;
	}

	rmsg->ops = OPS_MODIFY;
	return parse_arg(rmsg, argc, argv);
}

int sysmonctl_find(struct sysmon_rmsg_struct *rmsg, int argc, char *argv[])
{
	if(argc < 3)
	{
		printf("not enough arguments\n");
		return -1;
	}

	if(argc == 3)
	{
		if(strcmp(argv[2], "all"))
		{
			printf("invaild argument: %s\n", argv[2]);
			return -1;
		}
	}

	rmsg->ops = OPS_FIND;
	return parse_arg(rmsg, argc, argv);
}

char *parse_errno(int errnu)
{
	switch(errnu)
	{
		case RET_CONFLICT:
			return "confict";
		case RET_NOT_FOUND:
			return "not found";
		case RET_NO_MEMORY:
			return "no memory";
		case RET_INVAILD_OPS:
			return "invaild options";
		case RET_INVAILD_TYPE:
			return "invaild type";
		case RET_OVER_COUNT:
			return "over count";
		case RET_ERROR_MSG:
			return "error message";
		case RET_INVAILD_SYSCALL:
			return "invaild syscall";
	}
	return "unknown error";
}

void print_result(struct sysmon_sret_struct *sret, int num)
{
	int i;

	for(i = 0; i < num; i++)
	{
		printf("syscall %s", syscallarray[sret[i].sysno]);
		switch(sret[i].obj.type)
		{
			case TYPE_PID:
				printf(" pid %d", sret[i].obj.pid);
				break;
			case TYPE_TGID:
				printf(" tgid %d", sret[i].obj.tgid);
				break;
			case TYPE_COMM:
				printf(" comm %s", sret[i].obj.comm);
				break;
			default:
				printf("unknown");
		}
		printf(" timeout %luns\n", sret[i].timeout);
	}
}

int main(int argc, char *argv[])
{
	int ret, sockfd, len;
	void *payload;
	struct sysmon_rmsg_struct rmsg;
	struct sockaddr_un address;
	char *buffer;
	struct sysmon_smsg_struct *smsg;
	struct sysmon_sret_struct *sret;

	if(argc < 2)
	{
		printf("not enough arguments\n");
		return -1;
	}

	if(strcmp(argv[1], "add") == 0)
		ret = sysmonctl_add(&rmsg, argc -2, argv + 2);
	else if (strcmp(argv[1], "delete") == 0)
		ret = sysmonctl_delete(&rmsg, argc -2, argv + 2);
	else if (strcmp(argv[1], "modify") == 0)
		ret = sysmonctl_modify(&rmsg, argc -2, argv + 2);
	else if (strcmp(argv[1], "find") == 0)
		ret = sysmonctl_find(&rmsg, argc -2, argv + 2);
	else if (strcmp(argv[1], "help") == 0)
	{
		printf("%s add|delete|modify|find syscall [vlaue] pid|tgid|comm|all [vlaue] timeout [value]\n", argv[0]);
		return 0;
	}
	else if (strcmp(argv[1], "version") == 0)
	{
		printf("v1.0.0.0\n");
		printf("author: wang1131695576@outlook.com\n");
		return 0;
	}
	else
	{
		printf("unknown label: %s\n", argv[1]);
		return -1;
	}

	if(ret == -1)
		return -1;

	if ((sockfd = socket(AF_UNIX, SOCK_SEQPACKET, 0)) == -1) {
		printf("socekt failed(%s)\n", strerror(errno));
		return -1;
	}

	chdir(SOCKET_PATH);
	address.sun_family = AF_UNIX;
	strcpy (address.sun_path, SOCKET_NAME);

	if(connect(sockfd, (struct sockaddr *)&address, sizeof(struct sockaddr)) == -1)
	{
		printf("connect failed(%s)\n", strerror(errno));
		return -1;
	}
	if(write(sockfd, &rmsg, sizeof(struct sysmon_rmsg_struct)) == -1)
	{
		printf("send failed(%s)\n", strerror(errno));
		return -1;
	}

	buffer = malloc(MAX_LEN);
	if(buffer == NULL)
	{
		printf("malloc failed(%s)\n", strerror(errno));
		return -1;
	}

	len = read(sockfd, buffer, MAX_LEN);
	if(len == -1)
	{
		printf("read failed(%s)\n", strerror(errno));
		return -1;
	}

	if(len < sizeof(struct sysmon_smsg_struct))
	{
		printf("err buffer\n");
	}

	smsg = (struct sysmon_smsg_struct *)buffer;
	switch(smsg->ops)
	{
		case OPS_UNKNOWN:
		case OPS_ADD:
		case OPS_DELETE:
		case OPS_MODIFY:
			if(smsg->errnu != RET_SUCCESS)
				printf("%s\n", parse_errno(smsg->errnu));
			break;
		case OPS_FIND:
			if(smsg->errnu != RET_SUCCESS)
				printf("%s\n", parse_errno(smsg->errnu));
			else
			{
				if(len < sizeof(struct sysmon_smsg_struct) + smsg->retnum * sizeof(struct sysmon_sret_struct))
				{
					printf("err result\n");
					return -1;
				}

				print_result((struct sysmon_sret_struct *)(smsg + 1), smsg->retnum);
			}
			break;
		default:
			printf("unknow options\n");
			return -1;
	}
	return 0;
}
