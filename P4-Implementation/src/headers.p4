/* Copyright 2022-present University of Tuebingen, Chair of Communication Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Steffen Lindner (steffen.lindner@uni-tuebingen.de)
 */

#ifndef _HEADERS_
#define _HEADERS_

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<16> ether_type_t;
typedef bit<32> reg_index_t;
typedef bit<32> seq_t;

#define CPU_PORT 320
#define FABRIC_HEADER_TYPE_CPU  5
const ether_type_t ETHERTYPE_IPV4 = 0x800;
const ether_type_t ETHERTYPE_MONITOR = 0xBB02;
const ether_type_t ETHERTYPE_MPLS = 0x8847;
const ether_type_t ETHERTYPE_ARP = 0x0806;
const ether_type_t ETHERTYPE_BF_FABRIC = 0x9000;

const bit<8> IP_PROTOCOL_UDP = 17;
const bit<8> IP_PROTOCOL_TCP = 6;
const bit<8> IP_PROTOCOL_P4TG = 110;
const bit<8> IP_PROTOCOL_GRE = 47;
const bit<8> IP_PROTOCOL_IPIP = 4;
const bit<16> UDP_VxLAN_PORT = 4789;
const bit<16> UDP_P4TG_PORT = 50083;
const bit<16> TCP_P4TG_PORT = 50083;

const bit<2> TUNNEL_NONE = 0;
const bit<2> TUNNEL_VXLAN = 1;
const bit<2> TUNNEL_GRE = 2;
const bit<2> TUNNEL_IPIP = 3;

const bit<8> TG_MODE_ANALYZE = 4;

header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header fabric_header_h {
    bit<3> packetType;
    bit<2> headerVersion;
    bit<2> packetVersion;
    bit<1> pad1;

    bit<3> fabricColor;
    bit<5> fabricQos;

    bit<8> dstDevice;
    bit<16> dstPortOrGroup;
}

header fabric_header_cpu_h {
    bit<5> egressQueue;
    bit<1> txBypass;
    bit<2> reserved;

    bit<16> ingressPort;
    bit<16> ingressIfindex;
    bit<16> ingressBd;

    bit<16> reasonCode;
}

header fabric_payload_header_h {
    bit<16> etherType;
}

header arp_t {
    bit<16> hardwareaddr_t;
    bit<16> protoaddr_t;
    bit<8> hardwareaddr_s;
    bit<8> protoaddr_s;
    bit<16> op;
    mac_addr_t src_mac_addr;
    ipv4_addr_t src_ip_addr;
    mac_addr_t dst_mac_addr;
    ipv4_addr_t dst_ip_addr;
}


header mpls_h {
    bit<20> label;
    bit<3> tc; // traffic class
    bit<1> bos; // bottom of stack
    bit<8> ttl;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> len;
    bit<16> checksum;
}

header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_num;
    bit<32> ack_num;
    bit<4> len;
    bit<4> res; // 3 + 1(ECN)
    bit<1> CWR;
    bit<1> ECE;
    bit<1> URG;
    bit<1> ACK;
    bit<1> PSH;
    bit<1> RST;
    bit<1> SYN;
    bit<1> FIN;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header ipv4_udp_lookahead_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> len;
    bit<16> checksum;
}

// 剥离出udp_header，只保留p4_header字段
header path_monitor_t {
    seq_t seq;
    bit<48> tx_tstmp;
    bit<8> app_id;
}

header pkg_gen_t {
    bit<3> pad;
    bit<2> pipe;
    bit<3> app_id;
    bit<8> pad1;
    bit<16> batch_id;
    bit<16> pkt_id;
}

header monitor_t {
    bit<48> tstmp;
    bit<64> byte_counter_l1;
    bit<64> byte_counter_l2;
    bit<64> packet_loss;
    bit<48> app_counter;
    bit<40> out_of_order;
    bit<9> port;
    bit<15> index;
}

header vxlan_header_t {
    bit<8> vxlan_flags;
    bit<24> vxlan_reserved;
    bit<24> vxlan_vni;
    bit<8> vxlan_reserved2;
}

header gre_t {
    bit<1> C_flag;          // setting
    bit<1> R_flag;          // 0
    bit<1> K_flag;          // setting
    bit<1> S_flag;          // setting
    bit<1> strict_flag;     // setting 
    bit<3> recur;           // 1
    bit<5> flags;           // 0
    bit<3> ver;             // 0
    bit<16> protocol;       // 0x0800
}

header gre_option_checksum_t {
    bit<32> checksum;
}

header gre_option_key_t {
    bit<32> key;
}

header gre_option_sequence_t {
    bit<32> sequence;
}

struct header_t {
    ethernet_h ethernet;
    ethernet_h inner_ethernet;
    fabric_header_h         fabric_header;
    fabric_header_cpu_h     fabric_header_cpu;
    fabric_payload_header_h fabric_payload_header;   
    mpls_h[15] mpls_stack;
    ipv4_t ipv4;
    ipv4_t inner_ipv4;
    pkg_gen_t pkt_gen;
    udp_t udp; // for vxlan tunnel
    udp_t inner_udp;
    tcp_t tcp;
    monitor_t monitor;
    path_monitor_t path;
    vxlan_header_t vxlan;
    gre_t gre;
    gre_option_checksum_t gre_option_checksum;
    gre_option_key_t gre_option_key;
    gre_option_sequence_t gre_option_sequence;
    arp_t arp;
}

struct ingress_metadata_t {
    bool checksum_err;
    bit<32> rtt;
    bit<32> lost_packets;
    bit<16> rand_value;
    bit<19> iat_rand_value;
    bit<32> iat;
    bit<32> iat_diff_for_mae;
    bit<1> iat_mae_reset;
    bit<32> src_mask;
    bit<32> dst_mask;
    bit<32> mean_iat_diff;
    PortId_t ig_port;
    bit<2> tunnel; // 拓展为2bit，无隧道封装，vxaln隧道，gre隧道，ipip隧道共四种情况
    bit<1> arp_reply;
    bit<8> tg_mode;
    bit<1> send_to_cpu;
    bit<1> from_cpu;
}

struct egress_metadata_t {
    bit<1> monitor_type;
    PortId_t rx_port;
    bit<16> checksum_udp_tmp;
    bit<16> checksum_tcp_tmp;
    bit<32> checksum_add_udp_ip_src;
    bit<32> checksum_add_udp_ip_dst;
    ipv4_addr_t ipv4_src;
    ipv4_addr_t ipv4_dst;
}

struct iat_rtt_monitor_t {
    bit<32> iat;
    bit<32> rtt;
    PortId_t port;
}


#endif /* _HEADERS_ */
