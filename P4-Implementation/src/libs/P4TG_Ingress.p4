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
 
#include "./IAT.p4"
#include "./RTT.p4"
#include "./ingress/Frame_Type_Monitor.p4"

control P4TG_Ingress (
    inout header_t hdr,
    inout ingress_metadata_t ig_md, in ingress_intrinsic_metadata_t ig_intr_md, in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    IAT() iat;
    RTT() rtt;
    Frame_Type_Monitor() frame_type;

    // poisson
    Random<bit<16>>() rand;

    Register<bit<32>, PortId_t>(512, 0) rx_seq;
    //Register<bit<32>, _>(32, 0) lost_packets;
    Add_64_64(512) lost_packets;
    Add_64_64(512) out_of_order;

    RegisterAction<bit<32>, PortId_t, bit<32>>(rx_seq) get_rx = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;

            if(hdr.path.seq >= value) {
                value = hdr.path.seq + 1;
            }
            else if(value - hdr.path.seq > 2147483648) {
                value = hdr.path.seq + 1;
                //ig_md.overflow = 1;
                //read_value = hdr.path.seq;
            }
            else {
                value = value;
            }
        }
    };

    action port_forward(PortId_t e_port) {
            ig_tm_md.ucast_egress_port = e_port;
    }

    action forward_monitor(PortId_t e_port, bit<15> index) {
            ig_tm_md.ucast_egress_port = e_port;
            //ig_tm_md.bypass_egress = 1w1;

            hdr.monitor.index = index;
    }

    action mc_forward(bit<16> mcid) {
        ig_tm_md.mcast_grp_a = mcid;
    }

    action make_digest() {
        ig_dprsr_md.digest_type = 1;
    }

    action make_digest_and_forward(PortId_t e_port, bit<15> index) {
        ig_dprsr_md.digest_type = 1;
        ig_tm_md.ucast_egress_port = e_port;

        hdr.monitor.index = index;
        //hdr.monitor.app_id = app_id;
    }

    table tg_forward {
        key = {
              ig_intr_md.ingress_port: exact;
              hdr.pkt_gen.app_id: exact;
              ig_md.rand_value: range;
          }
        actions = {
              port_forward;
              mc_forward;
        }
        size = 64;
    }

    table monitor_forward {
        key = {
              ig_intr_md.ingress_port: exact;
              hdr.monitor.index: exact;
        }
        actions = {
            port_forward;
            forward_monitor;
            mc_forward;
            make_digest;
            make_digest_and_forward;
        }
        size = 256;
    }

    table forward {
        key = {
              ig_intr_md.ingress_port: exact;
          }
        actions = {
              port_forward;
        }
        size = 64;
    }


    action nop() {}

    // this table checks if a packet was received on an ingress port
    table is_ingress {
        key = {
            ig_intr_md.ingress_port: exact;
        }
        actions = {
            nop;

        }
        size = 64;
    }

    // this table is used to activate/deactivate
    // iat monitoring
    table monitor_iat {
        key = {
            ig_intr_md.ingress_port: lpm;
        }
        actions = {
            nop;
        }
        size = 1;
    }

    //TODO: For TCP connection mode
    action drop() {
        ig_dprsr_md.drop_ctl = 0x1;
    }

    action syn_to_synAck() {
        // 交换内外层ip源/目的地址，tcp源/目的端口号
        bit<32> tmp_ip_addr = hdr.inner_ipv4.src_addr;
        hdr.inner_ipv4.src_addr = hdr.inner_ipv4.dst_addr;
        hdr.inner_ipv4.dst_addr = tmp_ip_addr;

        bit<16> tmp_tcp_port = hdr.tcp.src_port;
        hdr.tcp.src_port = hdr.tcp.dst_port;
        hdr.tcp.dst_port = tmp_tcp_port;

        // 将syn包转换成syn_ack包
        hdr.tcp.ack_num = 1;
        hdr.tcp.seq_num = 0;
        hdr.tcp.ACK = 1;
        hdr.tcp.SYN = 1;

        // ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
        // ig_tm_md.bypass_egress = 1w1;
    }

    action syn_to_synAck_o() {
        // 交换内外层ip源/目的地址，tcp源/目的端口号
        bit<32> tmp_ip_addr = hdr.inner_ipv4.src_addr;
        hdr.inner_ipv4.src_addr = hdr.inner_ipv4.dst_addr;
        hdr.inner_ipv4.dst_addr = tmp_ip_addr;
        bit<32> tmp_o_ip_addr = hdr.ipv4.src_addr;
        hdr.ipv4.src_addr = hdr.ipv4.dst_addr;
        hdr.ipv4.dst_addr = tmp_o_ip_addr;

        bit<16> tmp_tcp_port = hdr.tcp.src_port;
        hdr.tcp.src_port = hdr.tcp.dst_port;
        hdr.tcp.dst_port = tmp_tcp_port;

        // 将syn包转换成syn_ack包
        hdr.tcp.ack_num = 1;
        hdr.tcp.seq_num = 0;
        hdr.tcp.ACK = 1;
        hdr.tcp.SYN = 1;

        // ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
        // ig_tm_md.bypass_egress = 1w1;
    }

    action synAck_to_ack() {
        // 交换内外层ip源/目的地址，tcp源/目的端口号
        bit<32> tmp_ip_addr = hdr.inner_ipv4.src_addr;
        hdr.inner_ipv4.src_addr = hdr.inner_ipv4.dst_addr;
        hdr.inner_ipv4.dst_addr = tmp_ip_addr;

        bit<16> tmp_tcp_port = hdr.tcp.src_port;
        hdr.tcp.src_port = hdr.tcp.dst_port;
        hdr.tcp.dst_port = tmp_tcp_port;

        // 将syn_ack包转换成ack包
        hdr.tcp.ack_num = 1;
        hdr.tcp.seq_num = 1;
        hdr.tcp.ACK = 1;
        hdr.tcp.SYN = 0;

        // ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
        // ig_tm_md.bypass_egress = 1w1;
    }

    action synAck_to_ack_o() {
        // 交换内外层ip源/目的地址，tcp源/目的端口号
        bit<32> tmp_ip_addr = hdr.inner_ipv4.src_addr;
        hdr.inner_ipv4.src_addr = hdr.inner_ipv4.dst_addr;
        hdr.inner_ipv4.dst_addr = tmp_ip_addr;
        bit<32> tmp_o_ip_addr = hdr.ipv4.src_addr;
        hdr.ipv4.src_addr = hdr.ipv4.dst_addr;
        hdr.ipv4.dst_addr = tmp_o_ip_addr;

        bit<16> tmp_tcp_port = hdr.tcp.src_port;
        hdr.tcp.src_port = hdr.tcp.dst_port;
        hdr.tcp.dst_port = tmp_tcp_port;

        // 将syn_ack包转换成ack包
        hdr.tcp.ack_num = 1;
        hdr.tcp.seq_num = 1;
        hdr.tcp.ACK = 1;
        hdr.tcp.SYN = 0;

        // ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
        // ig_tm_md.bypass_egress = 1w1;
    }

    table tcp_connection_mode {
        key = {
            // hdr.ipv4.isValid(): exact;
            hdr.tcp.SYN: exact;
            hdr.tcp.ACK: exact;
        }

        actions = {
            syn_to_synAck();
            syn_to_synAck_o();
            synAck_to_ack();
            synAck_to_ack_o();
            drop();
        }

        size = 8;

        const entries = {
            (1, 0) : syn_to_synAck();
            (1, 1) : synAck_to_ack();
            // (true, 1, 0) : syn_to_synAck_o();
            // (true, 1, 1) : synAck_to_ack_o();
            // (0, 1) : drop();
        }
    }

    apply {
        // monitor iats and send to controller
        // limited by meter
        if(monitor_iat.apply().hit) {
            iat.apply(hdr, ig_md, ig_intr_md, ig_dprsr_md);
        }

        // monitor frame types
        frame_type.apply(hdr, ig_md, ig_intr_md);

        // random value used for poisson traffic
        ig_md.rand_value = rand.get();

        ig_md.ig_port = ig_intr_md.ingress_port;

        bit<64> dummy = 0;

        // TCP连接建立模式syn包处理
        // tcp_connection_mode.apply();

        if ((hdr.inner_udp.isValid() && hdr.inner_udp.dst_port == UDP_P4TG_PORT) || (hdr.tcp.isValid() && hdr.tcp.dst_port == TCP_P4TG_PORT)) {   // this is P4TG traffic
            if(is_ingress.apply().hit) {
                // calculate rtt and send to controller
                // limited by meter
                rtt.apply(hdr, ig_md, ig_intr_md, ig_dprsr_md);

                // get next expected rx
                bit<32> r_seq = get_rx.execute(ig_md.ig_port);

                bit<32> m = max(r_seq, hdr.path.seq);
                bit<32> diff = (hdr.path.seq - r_seq);

                if(m == hdr.path.seq) { // packet loss
                    lost_packets.apply(dummy, (bit<64>) diff, (bit<32>)ig_md.ig_port);
                }
                else { // sequence number lower than expected
                    out_of_order.apply(dummy, 1, (bit<32>)ig_md.ig_port);
                }
            }
        }
        else if(hdr.monitor.isValid()) {
            bit<64> reordered_packets = 0;
            monitor_forward.apply();

            lost_packets.apply(hdr.monitor.packet_loss, 0, (bit<32>)ig_md.ig_port);

            out_of_order.apply(reordered_packets, 0, (bit<32>)ig_md.ig_port);

            hdr.monitor.out_of_order = (bit<40>) reordered_packets;
        }

        if(hdr.pkt_gen.isValid() && !hdr.monitor.isValid()) {
            tg_forward.apply();
        }
        else {
            if(!hdr.monitor.isValid() && ig_md.send_to_cpu == 0 && ig_md.from_cpu == 0) {
                forward.apply();
            }
        }

   }
}
