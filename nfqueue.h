#if !defined(NFQUEUE_H)
# define NFQUEUE_H

#define NF_PREROUTING 0
#define NF_POSTROUTING 4

#define DEFAULT_QUEUE_NUM 65109
#define DEFAULT_QUEUE_MAXLEN 4096

int do_nfqueue(struct config *conf);

#endif

