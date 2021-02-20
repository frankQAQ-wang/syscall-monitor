#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <syscall.h>
#include <limits.h>
#include <sys/un.h>
#include <time.h>
#include <signal.h>
#include <sys/time.h>

#define _S(syscallno, name) name,
static char *syscallarray[] = {
#include "syscall_table.h"
	NULL
};

#include "sysmond.h"

#define LISTEN_NUM 10
#define MAX_LEN (10*1024*1024)
#define MAX_EVENTS 16

struct list_head hreq[LISTEN_NUM];
int memlock;
int hashlock;
unsigned long req_heart;

static char *trans_task_policy(unsigned int policy)
{
	switch(policy)
	{
		case SCHED_NORMAL:
			return "SCHED_NORMAL";
		case SCHED_FIFO:
			return "SCHED_FIFO";
		case SCHED_RR:
			return "SCHED_RR";
		case SCHED_BATCH:
			return "SCHED_BATCH";
		case SCHED_IDLE:
			return "SCHED_IDLE";
		case SCHED_DEADLINE:
			return "SCHED_DEADLINE";
		default:
			return "unknown";
	}
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

void add_req(struct sysmon_req_struct *req)
{
	hashlock = req->seq % LISTEN_NUM;
	list_add_tail(&req->req, hreq + hashlock);
	hashlock = -1;
}

void delete_req(unsigned int seq)
{
	struct sysmon_req_struct *req;

	hashlock = seq % LISTEN_NUM;
	list_for_each_entry(req, hreq + hashlock, req)
		if(req->seq == seq) 
		{
			list_del(&req->req);
			memlock = 1;
			free(req);
			memlock = 0;
			hashlock = -1;
			return;
		}
	hashlock = -1;
}

int find_req(unsigned int seq)
{
	int fd;
	struct sysmon_req_struct *req;

	fd = -1;
	hashlock = seq % LISTEN_NUM;
	list_for_each_entry(req, hreq + hashlock, req)
		if(req->seq == seq)
			fd = req->fd;
	hashlock = -1;
	return fd;
}

int sysmon_module_init()
{
	int fd;
	struct sockaddr_nl src_addr;

	fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_SYSMON);
	if (fd == -1) {
		printf("module: socekt failed(%s)\n", strerror(errno));
		return -1;
	}

	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();
	src_addr.nl_groups = 1;

	if (bind(fd, (struct sockaddr *)&src_addr, sizeof(src_addr)) == -1) {
		printf("module: bind failed(%s)\n", strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

int create_dir(char *path)
{
	char *pos, *cur;
	char dirname[NAME_MAX];
	int start, end, len;

	start = 0;
	end = strlen(path) - 1;
	pos = path;

	while(pos[start] == '/')
		start ++;

	while(pos[end] == '/')
		end --;

	cur = strchr(pos + start, '/');
	while(cur != NULL)
	{
		if(cur - path > end)
			break;
		if(pos != cur)
		{
			memcpy(dirname, pos, cur - pos);
			dirname[cur - pos] = 0;
			if(mkdir(dirname, 0755) == -1 && errno != EEXIST)
			{
				printf("dir: mkdir %s failed(%s)\n", dirname, strerror(errno));
				return -1;
			}
			if(chdir(dirname) == -1 && errno != EEXIST)
			{
				printf("dir: chdir %s failed(%s)\n", dirname, strerror(errno));
				return -1;
			}
		}
		pos = cur + 1;
		cur = strchr(pos, '/');
	}

	if(mkdir(pos, 0775) == -1 && errno != EEXIST)
	{
		printf("dir: mkdir %s failed(%s)\n", pos, strerror(errno));
		return -1;
	}
	chdir(pos);

	return 0;
}

int sysmon_server_init()
{
	int fd;
	struct sockaddr_un server;

	if(create_dir(SOCKET_PATH) == -1)
		return -1;

	unlink(SOCKET_NAME);
	fd = socket (AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK, 0);
	if(fd == -1)
	{
		printf("server: socekt failed(%s)\n", strerror(errno));
		return -1;
	}

	server.sun_family = AF_UNIX;
	strcpy(server.sun_path, SOCKET_NAME);
	if(bind (fd, (struct sockaddr *)&server, sizeof(struct sockaddr_un)) == -1)
	{
		printf("server: bind failed(%s)\n", strerror(errno));
		close(fd);
		return -1;
	}

	if(listen(fd, LISTEN_NUM) == -1)
	{
		printf("server: listen failed(%s)\n", strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

void signalhandler(int signo)
{
	int i;
	struct sysmon_req_struct *req, *next;
	struct timespec time;

	clock_gettime(CLOCK_REALTIME, &time);
	switch (signo)
	{
		case SIGALRM:
			if(memlock)
				return;
			for(i = 0; i < LISTEN_NUM; i++)
			{
				if(hashlock == i)
					continue;

				list_for_each_entry_safe(req, next, hreq + i, req)
				{
					if(time.tv_sec - req->stime.tv_sec > 30)
					{
						list_del(&req->req);
						free(req);
					}
					else
						continue;
				}
			}
			break;
	}
}

int main()
{
	int sfd, efd, afd, cfd, rfd;
	int n, i, len, ret;
	int pos, cur;
	int flag;
	unsigned char *buff;
	struct nlmsghdr *nlh;
	struct epoll_event event;
	struct epoll_event events[MAX_EVENTS];
	struct sockaddr_nl dest_addr;
	struct sysmon_smsg_struct *smsg;
	struct sysmon_srecord_struct *srecord;
	struct sysmon_rmsg_struct *rmsg;
	char recordbuff[1024];
	struct sysmon_req_struct *req;
	struct sockaddr_un client_address;
	int client_len;
	struct itimerval new_value, old_value;
	char stime[64];

	sfd = sysmon_module_init();
	if(sfd == -1)
		return -1;

	afd = sysmon_server_init();
	if(afd == -1)
		return -1;

	efd = epoll_create1(0);
	if (efd == -1)
	{
		printf("fail: epoll_create(%s)\n", strerror(errno));
		return -1;
	}

	for(i = 0; i < LISTEN_NUM; i++)
		INIT_LIST_HEAD(hreq + i);

	event.data.fd = sfd;
	event.events = EPOLLIN | EPOLLET;
	if(epoll_ctl(efd, EPOLL_CTL_ADD, sfd, &event) == -1)
	{
		printf("fail: epoll_ctl(%s)\n", strerror(errno));
		return -1;
	}

	event.data.fd = afd;
	event.events = EPOLLIN | EPOLLET;
	if(epoll_ctl(efd, EPOLL_CTL_ADD, afd, &event) == -1)
	{       
		printf("fail: epoll_ctl(%s)\n", strerror(errno));
		return -1;
	}

	if(create_dir(RECORD_PATH) == -1)
	{
		printf("fail: mkdir %s(%s)\n", RECORD_PATH, strerror(errno));
		return -1;
	}

	rfd = open(RECORD_FILE, O_CREAT | O_WRONLY | O_APPEND);
	if(rfd == -1)
	{
		printf("fail: open(%s)\n", strerror(errno));
		return -1;
	}

	memlock = 0;
	hashlock = -1;
	req_heart = 0;

	buff = malloc(MAX_LEN);
	if(buff == NULL)
	{
		printf("fail: malloc(%s)\n", strerror(errno));
		return -1;
	}

	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0;
	dest_addr.nl_groups = 0;
	len = sizeof(struct sockaddr_nl);

	client_address.sun_family = AF_UNIX;
	strcpy(client_address.sun_path, SOCKET_NAME);

	signal(SIGALRM, signalhandler);
	new_value.it_value.tv_sec = 10;
	new_value.it_value.tv_usec = 0;
	new_value.it_interval.tv_sec = 30;
	new_value.it_interval.tv_usec = 0;
	setitimer(ITIMER_REAL, &new_value, &old_value);

	while (1)
	{
		n = epoll_wait (efd, events, MAX_EVENTS, -1);
		for (i = 0; i < n; i++)
		{
			pos = 0;
			cur = 0;
			if(events[i].data.fd == sfd)
			{
				while(1)
				{
					ret = recvfrom(sfd, buff + pos, MAX_LEN - pos, MSG_DONTWAIT, (struct sockaddr *)&dest_addr, &len);
					if(ret == -1)
						break;

					pos += ret;
					if(pos >= MAX_LEN)
						break;
				}
				for(cur = 0; cur < pos;)
				{
					if(pos - cur < NLMSG_SPACE(sizeof(struct sysmon_smsg_struct)))
						break;

					nlh = (struct nlmsghdr *)(buff + cur);
					smsg = NLMSG_DATA(buff + cur);
					cur += NLMSG_HDRLEN;
					switch(smsg->ops)
					{
						case OPS_UNKNOWN:
						case OPS_ADD:
						case OPS_DELETE:
						case OPS_MODIFY:
							cfd = find_req(nlh->nlmsg_seq);
							if(cfd != -1)
							{
								if(write(cfd, smsg, sizeof(struct sysmon_smsg_struct)) == -1)
								{
									epoll_ctl(efd, EPOLL_CTL_DEL, cfd, NULL);
									close(cfd);
								}
							}
							delete_req(nlh->nlmsg_seq);
							cur += NLMSG_ALIGN(sizeof(struct sysmon_smsg_struct));
							break;
						case OPS_FIND:
							if(pos - cur < NLMSG_ALIGN(smsg->retnum * sizeof(struct sysmon_sret_struct)))
								break;
							cfd = find_req(nlh->nlmsg_seq);
							if(cfd != -1)
							{
								if(write(cfd, smsg, sizeof(struct sysmon_smsg_struct) + smsg->retnum * sizeof(struct sysmon_sret_struct)) == -1)
								{
									epoll_ctl(efd, EPOLL_CTL_DEL, cfd, NULL);
									close(cfd);
								}
							}
							delete_req(nlh->nlmsg_seq);
							cur += NLMSG_ALIGN(sizeof(struct sysmon_smsg_struct) + smsg->retnum * sizeof(struct sysmon_sret_struct));
							break;
						case OPS_RECORD:
							if(pos - cur < NLMSG_ALIGN(sizeof(struct sysmon_smsg_struct) + sizeof(struct sysmon_srecord_struct)))
								break;
							srecord = (struct sysmon_srecord_struct *)(buff + cur + sizeof(struct sysmon_smsg_struct));
							ctime_r(&srecord->stime.tv_sec, stime);
							stime[strlen(stime) > 0 ? strlen(stime) - 1 : 0] = 0;
							sprintf(recordbuff, "catch: syscall = %s, cpu = %d, state = %s, pcomm = %s(%d), tcomm = %s(%d), comm = %s(%d), stime = %s.%lu, ctime = %lu.%lus\n", syscallarray[srecord->sysno], srecord->cpu, trans_task_state(srecord->state), srecord->pcomm, srecord->ppid, srecord->tcomm, srecord->tgid, srecord->comm, srecord->pid, stime, srecord->stime.tv_nsec, srecord->ctime.tv_sec - srecord->stime.tv_sec, srecord->ctime.tv_nsec - srecord->stime.tv_nsec);
							sprintf(recordbuff + strlen(recordbuff), "current: state = %s, pcomm = %s(%d), tcomm = %s(%d), comm = %s(%d), prio = %d, policy = %s, durtime = %lu.%lus\n", trans_task_state(srecord->curr_state), srecord->curr_pcomm, srecord->curr_ppid, srecord->curr_tcomm, srecord->curr_tgid, srecord->curr_comm, srecord->curr_pid, srecord->curr_prio, trans_task_policy(srecord->curr_policy), srecord->curr_durtime/(unsigned long)1000000000, srecord->curr_durtime%(unsigned long)1000000000);
							sprintf(recordbuff + strlen(recordbuff), "stack:\n%s\n", srecord->stack);
							write(rfd, recordbuff, strlen(recordbuff));
							cur += NLMSG_ALIGN(sizeof(struct sysmon_smsg_struct) + sizeof(struct sysmon_srecord_struct));
							break;
						default:
							printf("ops = %d\n", smsg->ops);
					}
				}
			}
			else if(events[i].data.fd == afd)
			{
				cfd = accept(afd, (struct sockaddr *)&client_address, (socklen_t *)&client_len);
				if (cfd == -1)
					printf("fail: accept(%s)\n", strerror(errno));
				else
				{
					if(fcntl(cfd, F_GETFL, &flag) == -1)
					{
						printf("fail: fcntl(%s)\n", strerror(errno));
						close(cfd);
					}
					else
					{
						flag |= O_NONBLOCK;
						if(fcntl(cfd, F_SETFL, flag) == -1)
						{
							printf("fail: fcntl(%s)\n", strerror(errno));
							close(cfd);
						}
						else
						{
							event.data.fd = cfd;
							event.events = EPOLLIN | EPOLLET | EPOLLERR | EPOLLRDHUP;
							if(epoll_ctl(efd, EPOLL_CTL_ADD, cfd, &event) == -1)
							{
								printf("fail: epoll_ctl(%s)\n", strerror(errno));
								close(cfd);
							}
						}
					}
				}
			}
			else
			{
				if(events[i].events & EPOLLERR || events[i].events & EPOLLRDHUP)
				{
					epoll_ctl(efd, EPOLL_CTL_DEL, events[i].data.fd, NULL);
					close(events[i].data.fd);
				}
				else
				{
					while(1)
					{
						ret = read(events[i].data.fd, buff + pos + NLMSG_HDRLEN, MAX_LEN - pos - NLMSG_HDRLEN);
						if(ret == -1)
							break;

						pos += ret;
						if(pos >= MAX_LEN - NLMSG_HDRLEN)
							break;
					}

					if(pos >= sizeof(struct sysmon_rmsg_struct))
					{

						memlock = 1;
						req = malloc(sizeof(struct sysmon_req_struct));
						memlock = 0;
						req->seq = req_heart ++;
						req->fd = events[i].data.fd;
						clock_gettime(CLOCK_REALTIME, &req->stime);
						INIT_LIST_HEAD(&req->req);
						add_req(req);

						nlh = (struct nlmsghdr *)buff;
						nlh->nlmsg_len = NLMSG_SPACE(sizeof(struct sysmon_rmsg_struct));
						nlh->nlmsg_type = NLMSG_MIN_TYPE;
						nlh->nlmsg_flags = NLM_F_REQUEST;
						nlh->nlmsg_seq = req->seq;
						nlh->nlmsg_pid = getpid();

						sendto(sfd, buff, NLMSG_SPACE(sizeof(struct sysmon_rmsg_struct)), 0, (struct sockaddr *)&dest_addr, sizeof(struct sockaddr_nl));
					}
				}
			}
		}
	}
	close(efd);
	close(afd);
	close(sfd);
	close(rfd);
	free(buff);
}
