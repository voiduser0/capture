#pragma once
#include <cstdint>

using u_char = uint8_t;				// 1 byte
using u_short = uint16_t;				// 2 byte
using u_int =  uint32_t;						// 4 byte

/*	ethernet
+--------------------------+-----------------------+--------+
|       6 byte                       |     6 byte                    |2 byte |
+--------------------------+-----------------------+--------+
|destination mac address |  source mac address | type |
+-------------------------+------------------------+--------+
*/

typedef struct {					// 14 byte
	u_char des_mac[6];			// 6 byte
	u_char src_mac[6];			// 6 byte
	u_short type;					// 2 byte
}ethernet_header;


// ---------------------------------------------------------------------

/*
|                 ARP header                       |
+----------+----------+------+-------+----------+--------------+----------+-------------------+---------------+
|   2 byte    | 2 byte     | 1byte | 1byte | 2 byte       | 6 byte           | 4 byte     |     6 byte            |     4 byte        |
+----------+----------+------+-------+----------+--------------+----------+-------------------+---------------+
| hardware | protocol | h_len |  ip_len  | operation | source mac | source ip |destination mac | destination ip |
+----------+----------+------+-------+----------+--------------+----------+-------------------+---------------+
*/

typedef struct {							// 28 byte
	u_short hardware_type;			// 2 byte
	u_short protocol_type;			// 2 byte
	u_char mac_length;					// 1 byte
	u_char ip_length;						// 1 byte
	u_short op_code;						// 2 byte
	u_char src_mac[6];					// 6 byte
	u_char src_ip[4];						// 4 byte
	u_char des_mac[6];					// 6 byte
	u_char des_ip[4];						// 4 byte
}arp_header;



// ---------------------------------------------------------------------


/* ipv4
+-------+------------+--------------+-------------------------+
| 4 bit     |   4 bit          |    8 bit         |          16 bit             |
+-------+------------+--------------+-------------------------+
|version | head length|  TOS            |        total length     |
+-------+------------+-----+---+----+-+-+-+----------------+
|          identification                         | |D|M|    offset         |
+-------------------+-----------------+-+-+-+----------------+
|       ttl                         |     protocal      |         checksum        |
+-------------------+---------------+-------------------------+
|                         source ip address                                          |
+---------------------------------------------------------------+
|                          destination ip address                                  |
+---------------------------------------------------------------+
*/


typedef struct {									// 20 byte
	u_char head_length : 4;					// header_length 4 bit
	u_char version : 4;							// version 4 bit , 
	u_char TOS;										// 1 byte
	u_short total_length;					    // 2 byte
	u_short identification;						// 2 byte
	u_short flag_offset;							// flag 3 bit , offset 13 bit
	u_char ttl;											// 1 byte
	u_char protocol;							    // 1 byte
	u_short checksum;						    // 2 byte
	u_int src_ip_addr;							    // 4 byte
	u_int des_ip_addr;							// 4 byte
}ip_header;

// ---------------------------------------------------------------------


/* ICMP
+--------+---------+-------------------------+
|  1 byte  |  1 byte  |        2 byte       |
+--------+---------+------------------------+
|   type   |   code   |       checksum      |
+-------------------+-----------------------+
|    identification   |       sequence      |
+-------------------+-----------------------+
|                  option                             |
+-------------------------------------------+
*/

typedef struct {						// ÷¡…Ÿ 8 byte
	u_char type;							// 1 byte
	u_char code;						// 1 byte
	u_short checksum;              // 2 byte
	u_short identification;         // 2 byte
	u_short sequence;               // 2 byte
}icmp_header;


// ---------------------------------------------------------------------


/* TCP
+----------------------+---------------------+
|         16 bit                |       16 bit             |
+----------------------+---------------------+
|      source port          |  destination port   |
+----------------------+---------------------+
|              sequence number                   |
+----------------------+---------------------+
|                 ack number                           |
+----+---------+-------+---------------------+
|head| reserved| flags  |     window size     |
+----+---------+-------+---------------------+
|     checksum             |   urgent pointer    |
+----------------------+---------------------+
*/

typedef struct {						// 20 byte
	u_short src_port;				    // 2 byte
	u_short des_port;				    // 2 byte
	u_int seq;								  // 4 byte
	u_int ack;								  // 4 byte
	u_char header_length;			  // 4 bit
	// reversed								3 bit
	u_char flags;						 // 9 bit
	u_short window_size;			  // 2 byte
	u_short checksum;				 // 2 byte
	u_short urgent;					 // 2 byte
}tcp_header;


// ---------------------------------------------------------------------


/* UDP
+---------------------+---------------------+
|        16 bit                  |        16 bit       |
+---------------------+---------------------+
|    source port            |   destination port  |
+---------------------+---------------------+
| data package length |       checksum      |
+---------------------+---------------------+
*/

typedef struct {					// 8 byte
	u_short src_port;			    // 2 byte
	u_short des_port;				// 2 byte
	u_short data_length;	    // 2 byte
	u_short checksum;			// 2 byte
}udp_header;


// ---------------------------------------------------------------------

/* DNS
+--------------------------+---------------------------+
|           16 bit             |1b |4b  |1b |1b |1b |1b|3b|4b |
+--------------------------+--+----+--+--+--+--+--+----+
|      identification      |QR| OP |AA|TC | RD|RA|..|Resp|
+--------------------------+--+----+--+--+--+--+--+----+
|         Questions        |       Answer RRs          |
+--------------------------+---------------------------+
|     Authority RR       |      Additional RRs       |
+--------------------------+---------------------------+
*/

typedef struct{							// 12 byte
	u_short identification;			// 2 byte
	u_short flags;						// 2 byte
	u_short question;					// 2 byte
	u_short answer;					// 2 byte
	u_short authority;				// 2 byte
	u_short additional;				// 2 byte
}dns_header;


typedef struct {
	// char* name;						// Non-fixed
	u_short query_type;			   // 2 byte
	u_short query_class;		  // 2 byte
}dns_question;

typedef struct  {
	// char* name							// Non-fixed
	u_short answer_type;				// 2 byte
	u_short answer_class;				 // 2 byte
	u_int TTL;									  // 4 byte
	u_short dataLength;				 // 2 byte
	//char* name							// Non-fixed
}dns_answer;