#ifndef __SYSMOND_H
#define __SYSMOND_H

#include "sysmon.h"

#define NETLINK_SYSMON  (MAX_LINKS - 1)

#define RECORD_PATH "/var/log/sysmon"
#define RECORD_FILE "record.log"

#define LIST_HEAD_INIT(name) { &(name), &(name) }

struct list_head {
	struct list_head *next, *prev;
}; 

static inline void INIT_LIST_HEAD(struct list_head *list)
{                                   
	list->next = list;
	list->prev = list;
}     

static inline void __list_add(struct list_head *new, struct list_head *prev, struct list_head *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next =  new;
}

static inline void list_add(struct list_head *new, struct list_head *head)
{
	__list_add(new, head, head->next);
}

static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
	__list_add(new, head->prev, head);
}

static inline void __list_del(struct list_head * prev, struct list_head * next)
{
	next->prev = prev;
	prev->next = next;
}

static inline void __list_del_entry(struct list_head *entry)
{               
	__list_del(entry->prev, entry->next);
}       

static inline void list_del(struct list_head *entry)
{
	__list_del_entry(entry);
	entry->next = NULL;
	entry->prev = NULL;
}

#define offsetof(TYPE, MEMBER)  ((size_t)&((TYPE *)0)->MEMBER)

#define container_of(ptr, type, member) ({                              \
		void *__mptr = (void *)(ptr);                                   \
		((type *)(__mptr - offsetof(type, member))); })

#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)

#define list_next_entry(pos, member) \
	list_entry((pos)->member.next, typeof(*(pos)), member)

#define list_for_each_entry(pos, head, member)                          \
	for (pos = list_first_entry(head, typeof(*pos), member);        \
			&pos->member != (head);                                    \
			pos = list_next_entry(pos, member))

#define list_for_each_entry_safe(pos, n, head, member)                  \
	for (pos = list_first_entry(head, typeof(*pos), member),        \
			n = list_next_entry(pos, member);                       \
			&pos->member != (head);                                    \
			pos = n, n = list_next_entry(n, member))

struct sysmon_req_struct
{
	unsigned int seq;
	int fd;
	struct timespec stime;
	struct list_head req;
};

#endif
