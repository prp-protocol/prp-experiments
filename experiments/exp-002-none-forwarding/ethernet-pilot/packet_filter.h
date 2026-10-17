#ifndef EXP002_PACKET_FILTER_H
#define EXP002_PACKET_FILTER_H
/* Explicit capture selection, not wire isolation or remote authentication. */
int pf_attach(int fd);
int pf_lock(int fd);
int pf_verify(int fd);
#endif
