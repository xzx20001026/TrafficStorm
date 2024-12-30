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

#include "./mpls_actions.p4"

control Header_Replace(
    inout header_t hdr,
    in egress_intrinsic_metadata_t eg_intr_md) {

    MPLS_Rewrite() mpls_rewrite_c;

    // IP replace
    Random<bit<32>>() src_rand;
    Random<bit<32>>() dst_rand;
    Random<bit<32>>() o_src_rand;
    Random<bit<32>>() o_dst_rand;

    bit<32> src_rand_value;
    bit<32> dst_rand_value;
    bit<32> o_src_rand_value;
    bit<32> o_dst_rand_value;

    bit<32> src_mask = 0; // P4TG源ip地址掩码
    bit<32> dst_mask = 0; // P4TG目ip地址掩码
    bit<32> outer_src_mask = 0; // 隧道源ip地址掩码
    bit<32> outer_dst_mask = 0; // 隧道目ip地址掩码

    action rewrite(mac_addr_t src_mac, mac_addr_t dst_mac, bit<32> s_ip, bit<32> d_ip, bit<32> s_mask, bit<32> d_mask, bit<8> tos, bit<16> inner_udp_s_port) {
            src_mask = s_mask & src_rand_value;
            dst_mask = d_mask & dst_rand_value;
            
            hdr.ethernet.dst_addr = dst_mac;
            hdr.ethernet.src_addr = src_mac;

            hdr.inner_ipv4.dst_addr = d_ip;
            hdr.inner_ipv4.src_addr = s_ip;
            hdr.inner_ipv4.diffserv = tos;

            hdr.inner_udp.src_port = inner_udp_s_port; // inner udp源端口字段
    }

    action rewrite_vxlan(mac_addr_t outer_src_mac, mac_addr_t outer_dst_mac, mac_addr_t inner_src_mac,
                        mac_addr_t inner_dst_mac, bit<32> inner_s_ip, bit<32> inner_d_ip, bit<32> s_mask, bit<32> d_mask, bit<8> inner_tos,
                        bit<32> outer_s_ip, bit<32> outer_d_ip, bit<8> outer_tos, bit<16> udp_source, bit<24> vni,
                        bit<16> inner_udp_s_port,
                        bit<32> outer_s_mask, bit<32> outer_d_mask) {
            outer_src_mask = outer_s_mask & o_src_rand_value;
            outer_dst_mask = outer_d_mask & o_dst_rand_value;

            src_mask = s_mask & src_rand_value;
            dst_mask = d_mask & dst_rand_value;

            hdr.ethernet.dst_addr = outer_dst_mac;
            hdr.ethernet.src_addr = outer_src_mac;

            hdr.inner_ethernet.dst_addr = inner_dst_mac;
            hdr.inner_ethernet.src_addr = inner_src_mac;

            hdr.ipv4.dst_addr = outer_d_ip;
            hdr.ipv4.src_addr = outer_s_ip;
            hdr.ipv4.diffserv = outer_tos;

            hdr.inner_ipv4.dst_addr = inner_d_ip;
            hdr.inner_ipv4.src_addr = inner_s_ip;
            hdr.inner_ipv4.diffserv = inner_tos;

            hdr.udp.src_port = udp_source; // vxlan隧道udp的源端口字段

            hdr.inner_udp.src_port = inner_udp_s_port; // inner udp源端口字段

            hdr.vxlan.vxlan_vni = vni;
    }

    action rewrite_gre(mac_addr_t src_mac, mac_addr_t dst_mac, 
                   bit<32> inner_s_ip, bit<32> inner_d_ip, bit<32> s_mask, bit<32> d_mask, bit<8> inner_tos,
                   bit<32> outer_s_ip, bit<32> outer_d_ip, bit<8> outer_tos,
                   bit<16> inner_udp_s_port,
                   bit<32> outer_s_mask, bit<32> outer_d_mask) {
        src_mask = s_mask & src_rand_value; 
        dst_mask = d_mask & dst_rand_value; 

        outer_src_mask = outer_s_mask & o_src_rand_value;
        outer_dst_mask = outer_d_mask & o_dst_rand_value;

        // 以太网字段重写
        hdr.ethernet.src_addr = src_mac;
        hdr.ethernet.dst_addr = dst_mac;

        // 外层L3层字段重写(GRE隧道)
        hdr.ipv4.src_addr = outer_s_ip;
        hdr.ipv4.dst_addr = outer_d_ip;
        hdr.ipv4.diffserv = outer_tos;

        // 内层L3字段重写(P4TG)
        hdr.inner_ipv4.dst_addr = inner_d_ip;
        hdr.inner_ipv4.src_addr = inner_s_ip;
        hdr.inner_ipv4.diffserv = inner_tos;

        // 内层L4字段重写(P4TG)
        hdr.inner_udp.src_port = inner_udp_s_port;
    }

    action rewrite_ipip(mac_addr_t src_mac, mac_addr_t dst_mac, 
                   bit<32> inner_s_ip, bit<32> inner_d_ip, bit<32> s_mask, bit<32> d_mask, bit<8> inner_tos,
                   bit<32> outer_s_ip, bit<32> outer_d_ip, bit<8> outer_tos,
                   bit<16> inner_udp_s_port,
                   bit<32> outer_s_mask, bit<32> outer_d_mask) {
        src_mask = s_mask & src_rand_value;
        dst_mask = d_mask & dst_rand_value;

        outer_src_mask = outer_s_mask & o_src_rand_value;
        outer_dst_mask = outer_d_mask & o_dst_rand_value;

        // 以太网字段重写
        hdr.ethernet.src_addr = src_mac;
        hdr.ethernet.dst_addr = dst_mac;

        // 外层L3层字段重写(IPIP隧道)
        hdr.ipv4.src_addr = outer_s_ip;
        hdr.ipv4.dst_addr = outer_d_ip;
        hdr.ipv4.diffserv = outer_tos;

        // 内层L3字段重写(P4TG)
        hdr.inner_ipv4.dst_addr = inner_d_ip;
        hdr.inner_ipv4.src_addr = inner_s_ip;
        hdr.inner_ipv4.diffserv = inner_tos;

        // 内层L4字段重写(P4TG)
        hdr.inner_udp.src_port = inner_udp_s_port;
    }

    table header_replace {
        key = {
            eg_intr_md.egress_port: exact;
            hdr.path.app_id: exact;
        }
        actions = {
            rewrite;
            rewrite_vxlan;
            rewrite_gre;
            rewrite_ipip;
        }
        size = 128;
    }

    action rewrite_tcp(mac_addr_t src_mac, mac_addr_t dst_mac, bit<32> s_ip, bit<32> d_ip, bit<32> s_mask, bit<32> d_mask, bit<8> tos, bit<16> tcp_s_port) {
            src_mask = s_mask & src_rand_value;
            dst_mask = d_mask & dst_rand_value;
            
            hdr.ethernet.dst_addr = dst_mac;
            hdr.ethernet.src_addr = src_mac;

            hdr.inner_ipv4.dst_addr = d_ip;
            hdr.inner_ipv4.src_addr = s_ip;
            hdr.inner_ipv4.diffserv = tos;

            hdr.tcp.src_port = tcp_s_port; // tcp源端口字段
    }

    action rewrite_vxlan_tcp(mac_addr_t outer_src_mac, mac_addr_t outer_dst_mac, mac_addr_t inner_src_mac,
                        mac_addr_t inner_dst_mac, bit<32> inner_s_ip, bit<32> inner_d_ip, bit<32> s_mask, bit<32> d_mask, bit<8> inner_tos,
                        bit<32> outer_s_ip, bit<32> outer_d_ip, bit<8> outer_tos, bit<16> udp_source, bit<24> vni,
                        bit<16> tcp_s_port,
                        bit<32> outer_s_mask, bit<32> outer_d_mask) {
            outer_src_mask = outer_s_mask & o_src_rand_value;
            outer_dst_mask = outer_d_mask & o_dst_rand_value;

            src_mask = s_mask & src_rand_value;
            dst_mask = d_mask & dst_rand_value;

            hdr.ethernet.dst_addr = outer_dst_mac;
            hdr.ethernet.src_addr = outer_src_mac;

            hdr.inner_ethernet.dst_addr = inner_dst_mac;
            hdr.inner_ethernet.src_addr = inner_src_mac;

            hdr.ipv4.dst_addr = outer_d_ip;
            hdr.ipv4.src_addr = outer_s_ip;
            hdr.ipv4.diffserv = outer_tos;

            hdr.inner_ipv4.dst_addr = inner_d_ip;
            hdr.inner_ipv4.src_addr = inner_s_ip;
            hdr.inner_ipv4.diffserv = inner_tos;

            hdr.udp.src_port = udp_source; // vxlan隧道udp的源端口字段

            hdr.tcp.src_port = tcp_s_port; // tcp源端口字段

            hdr.vxlan.vxlan_vni = vni;
    }

    action rewrite_gre_tcp(mac_addr_t src_mac, mac_addr_t dst_mac, 
                   bit<32> inner_s_ip, bit<32> inner_d_ip, bit<32> s_mask, bit<32> d_mask, bit<8> inner_tos,
                   bit<32> outer_s_ip, bit<32> outer_d_ip, bit<8> outer_tos,
                   bit<16> tcp_s_port,
                   bit<32> outer_s_mask, bit<32> outer_d_mask) {
        src_mask = s_mask & src_rand_value; 
        dst_mask = d_mask & dst_rand_value; 

        outer_src_mask = outer_s_mask & o_src_rand_value;
        outer_dst_mask = outer_d_mask & o_dst_rand_value;

        // 以太网字段重写
        hdr.ethernet.src_addr = src_mac;
        hdr.ethernet.dst_addr = dst_mac;

        // 外层L3层字段重写(GRE隧道)
        hdr.ipv4.src_addr = outer_s_ip;
        hdr.ipv4.dst_addr = outer_d_ip;
        hdr.ipv4.diffserv = outer_tos;

        // 内层L3字段重写(P4TG)
        hdr.inner_ipv4.dst_addr = inner_d_ip;
        hdr.inner_ipv4.src_addr = inner_s_ip;
        hdr.inner_ipv4.diffserv = inner_tos;

        // 内层L4字段重写(P4TG)
        hdr.tcp.src_port = tcp_s_port;
    }

    action rewrite_ipip_tcp(mac_addr_t src_mac, mac_addr_t dst_mac, 
                   bit<32> inner_s_ip, bit<32> inner_d_ip, bit<32> s_mask, bit<32> d_mask, bit<8> inner_tos,
                   bit<32> outer_s_ip, bit<32> outer_d_ip, bit<8> outer_tos,
                   bit<16> tcp_s_port,
                   bit<32> outer_s_mask, bit<32> outer_d_mask) {
        src_mask = s_mask & src_rand_value;
        dst_mask = d_mask & dst_rand_value;

        outer_src_mask = outer_s_mask & o_src_rand_value;
        outer_dst_mask = outer_d_mask & o_dst_rand_value;

        // 以太网字段重写
        hdr.ethernet.src_addr = src_mac;
        hdr.ethernet.dst_addr = dst_mac;

        // 外层L3层字段重写(IPIP隧道)
        hdr.ipv4.src_addr = outer_s_ip;
        hdr.ipv4.dst_addr = outer_d_ip;
        hdr.ipv4.diffserv = outer_tos;

        // 内层L3字段重写(P4TG)
        hdr.inner_ipv4.dst_addr = inner_d_ip;
        hdr.inner_ipv4.src_addr = inner_s_ip;
        hdr.inner_ipv4.diffserv = inner_tos;

        // 内层L4字段重写(P4TG)
        hdr.tcp.src_port = tcp_s_port;
    }

    table header_replace_tcp {
        key = {
            eg_intr_md.egress_port: exact;
            hdr.path.app_id: exact;
        }
        actions = {
            rewrite_tcp;
            rewrite_vxlan_tcp;
            rewrite_gre_tcp;
            rewrite_ipip_tcp;
        }
        size = 128;
    }

    action rewrite_o_iph() {
        hdr.ipv4.src_addr = hdr.ipv4.src_addr | outer_src_mask;
        hdr.ipv4.dst_addr = hdr.ipv4.dst_addr | outer_dst_mask;
    }

    action rewrite_inner_iph() {
        hdr.inner_ipv4.src_addr = hdr.inner_ipv4.src_addr | src_mask;
        hdr.inner_ipv4.dst_addr = hdr.inner_ipv4.dst_addr | dst_mask;
    }

    action rewrite_o_and_inner_iph() {
        hdr.ipv4.src_addr = hdr.ipv4.src_addr | outer_src_mask;
        hdr.ipv4.dst_addr = hdr.ipv4.dst_addr | outer_dst_mask;
        hdr.inner_ipv4.src_addr = hdr.inner_ipv4.src_addr | src_mask;
        hdr.inner_ipv4.dst_addr = hdr.inner_ipv4.dst_addr | dst_mask;
    }

    table tunnel_ip_replace {
        key = {
            hdr.ipv4.isValid(): exact;
            hdr.inner_ipv4.isValid(): exact;
        }

        actions = {
            rewrite_o_iph();
            rewrite_inner_iph();
            rewrite_o_and_inner_iph();
        }

        size = 8;

        const entries = {
            (true, false) : rewrite_o_iph();
            (false, true) : rewrite_inner_iph();
            (true, true) : rewrite_o_and_inner_iph();
        }
    }

    apply {
        src_rand_value = src_rand.get();
        dst_rand_value = dst_rand.get();
        o_src_rand_value = o_src_rand.get();
        o_dst_rand_value = o_dst_rand.get();

        // we only rewrite IP header for P4TG packets
        if (hdr.inner_udp.isValid() && hdr.inner_udp.dst_port == 50083) {
            header_replace.apply();
            // tunnel_ip_replace.apply();

            mpls_rewrite_c.apply(hdr, eg_intr_md);
        }
        else if (hdr.tcp.isValid() && hdr.tcp.dst_port == 50083) {
            header_replace_tcp.apply();
            // tunnel_ip_replace.apply();
        }

        tunnel_ip_replace.apply();
    }
}
