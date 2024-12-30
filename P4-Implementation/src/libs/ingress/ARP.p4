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

// Handles ARP requests
control ARP(inout header_t hdr, inout ingress_metadata_t ig_md, in ingress_intrinsic_metadata_t ig_intr_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    action answer_arp(PortId_t e_port, bit<1> valid, mac_addr_t src_addr) {
    }

    table arp_reply {
        key = {
            ig_intr_md.ingress_port: exact;
        }
        actions = {
            answer_arp;
        }
        size = 64;
    }

    apply {
        arp_reply.apply();
    }
}