#ifndef DEFINES_H
#define DEFINES_H

#define IP_SIZE(ip) ((((ip)->ip_hl) & 0x0f)*4)
const int SNAP_LEN = 1518;

// define the protocol types
const unsigned short PROTOCOL_ICMP = 0;
const unsigned short PROTOCOL_TCP_F = 1;    // occationally the same value on tcp header
const unsigned short PROTOCOL_TCP_S = 2;    // occationally the same value on tcp header
const unsigned short PROTOCOL_TCP_C = 3;
const unsigned short PROTOCOL_UDP = 4;

// the struct contain informations of IP and ID when ping
typedef struct _IPID_Info{
    unsigned int ip;
    unsigned short ICMPid;
    unsigned short IPid;
} IPID_Info;

// the struct contain informations of IP,ID,PORT,SEQ when TCP
typedef struct _TCP_Info{
    unsigned int ip;
    unsigned short ipID;
    unsigned short port;
    unsigned int seq;
} TCP_Info;

// the struct for udp scan
typedef struct _UDP_Info{
    unsigned int ip;
    unsigned short ipID;
    unsigned short port;
} UDP_Info;


#endif // DEFINES_H
