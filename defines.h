#ifndef DEFINES_H
#define DEFINES_H

#define IP_SIZE(ip) ((((ip)->ip_hl) & 0x0f)*4)
const int SNAP_LEN = 1518;

// the struct contain informations of IP and ID when ping
typedef struct _IPID_Info{
    unsigned int ip;
    unsigned short ICMPid;
    unsigned short IPid;
} IPID_Info;


#endif // DEFINES_H
