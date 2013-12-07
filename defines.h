#ifndef DEFINES_H
#define DEFINES_H

#define IP_SIZE(ip) ((((ip)->ip_hl) & 0x0f)*4)
const int SNAP_LEN = 1518;

// define the protocol types
const unsigned short PROTOCOL_ICMP = 0;
const unsigned short PROTOCOL_TCP_C = 1;
const unsigned short PROTOCOL_TCP_S = 2;
const unsigned short PROTOCOL_TCP_F = 3;

// the struct contain informations of IP and ID when ping
typedef struct _IPID_Info{
    unsigned int ip;
    unsigned short ICMPid;
    unsigned short IPid;
} IPID_Info;


#endif // DEFINES_H
