/* Copyright 2024-present University of Tuebingen, Chair of Communication Networks
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


control To_or_From_CPU(inout header_t hdr, inout ingress_metadata_t ig_md, in ingress_intrinsic_metadata_t ig_intr_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    action set_egress_port() {
        ig_md.from_cpu = 1;
        ig_tm_md.ucast_egress_port = (bit<9>)hdr.fabric_header.dstPortOrGroup;
        hdr.ethernet.ether_type = hdr.fabric_payload_header.etherType;
        hdr.fabric_header.setInvalid();
        hdr.fabric_header_cpu.setInvalid();
        hdr.fabric_payload_header.setInvalid();
        ig_tm_md.bypass_egress = 1w1;
    }

    action add_cpu_header() {

        hdr.fabric_header.setValid();
        hdr.fabric_header.packetType = FABRIC_HEADER_TYPE_CPU;
        hdr.fabric_header.headerVersion = 0;
        hdr.fabric_header.packetVersion = 0;
        hdr.fabric_header.pad1 = 0;
        hdr.fabric_header.fabricColor = 0;
        hdr.fabric_header.fabricQos = 0;
        hdr.fabric_header.dstDevice = 0;
        hdr.fabric_header.dstPortOrGroup = 0;

        hdr.fabric_header_cpu.setValid();
        hdr.fabric_header_cpu.reserved = 0;
        hdr.fabric_header_cpu.ingressIfindex = 0;
        hdr.fabric_header_cpu.ingressBd = 1;
        hdr.fabric_header_cpu.reasonCode = 0;
        hdr.fabric_header_cpu.ingressPort = (bit<16>)ig_intr_md.ingress_port;
        
        hdr.fabric_payload_header.setValid();
        hdr.fabric_payload_header.etherType = hdr.ethernet.ether_type;
        hdr.ethernet.ether_type = ETHERTYPE_BF_FABRIC;
        ig_tm_md.ucast_egress_port = CPU_PORT;
        
        ig_md.send_to_cpu = 1;
        ig_tm_md.bypass_egress = 1w1;
        
    }

    table from_cpu {
        key = {
            ig_intr_md.ingress_port: exact;
        }
        actions = {
            set_egress_port;
        }
        size = 1;
        const entries = {
            (CPU_PORT) : set_egress_port();
        }
    }

    table broadcast {
        key = {
            hdr.ethernet.dst_addr: exact;
            ig_md.send_to_cpu: exact;
            ig_md.from_cpu: exact;
        }
        actions = {
            add_cpu_header;
        }
        size = 1;
        const entries = {
            (0xffffffffffff, 0, 0) : add_cpu_header();
        }
    }

    table multicast {
        key = {
            hdr.ethernet.dst_addr: ternary;
            ig_md.send_to_cpu: exact;
            ig_md.from_cpu: exact;
        }
        actions = {
            add_cpu_header;
        }
        size = 1;
        const entries = {
            (0x01005e000000 &&& 0xffffff800000, 0, 0) : add_cpu_header();
        }
    }

    table Interconnect {
        key = {
            hdr.inner_ipv4.src_addr: exact;
            ig_md.send_to_cpu: exact;
            ig_md.from_cpu: exact;
        }
        actions = {
            add_cpu_header;
        }
        size = 32;
        const entries = {
            (0x1e65ee58, 0, 0) : add_cpu_header();
        }
    }

    apply {
        from_cpu.apply();
        broadcast.apply();
        multicast.apply();
        Interconnect.apply();
    }
}