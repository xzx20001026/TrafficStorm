#include "./libs/ingress/ARP.p4"
#include "./libs/ingress/To_or_From_CPU.p4"

@pa_no_overlay("ingress", "hdr.fabric_header.packetType")
@pa_no_overlay("ingress", "hdr.fabric_header.headerVersion")
@pa_no_overlay("ingress", "hdr.fabric_header.packetVersion")
@pa_no_overlay("ingress", "hdr.fabric_header.pad1")
@pa_no_overlay("ingress", "hdr.fabric_header.fabricColor")
@pa_no_overlay("ingress", "hdr.fabric_header.fabricQos")
@pa_no_overlay("ingress", "hdr.fabric_header.dstDevice")
@pa_no_overlay("ingress", "hdr.fabric_header.dstPortOrGroup")

@pa_no_overlay("ingress", "hdr.fabric_header_cpu.ingressBd")
@pa_no_overlay("ingress", "hdr.fabric_header_cpu.reasonCode")
@pa_no_overlay("ingress", "hdr.fabric_header_cpu.egressQueue")
@pa_no_overlay("ingress", "hdr.fabric_header_cpu.txBypass")
@pa_no_overlay("ingress", "hdr.fabric_header_cpu.reserved")
@pa_no_overlay("ingress", "hdr.fabric_header_cpu.ingressPort")
@pa_no_overlay("ingress", "hdr.fabric_header_cpu.ingressIfindex")

@pa_no_overlay("ingress", "hdr.fabric_payload_header.etherType")

control ingress(
    inout header_t hdr,
    inout ingress_metadata_t ig_md, in ingress_intrinsic_metadata_t ig_intr_md, in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    P4TG_Ingress() p4tg;
    ARP() arp;
    To_or_From_CPU() to_or_from_cpu;

    action set_mode(bit<8> mode) {
        ig_md.tg_mode = mode;
    }

    table tg_mode {
        key = {
            ig_intr_md.ingress_port: lpm;
        }
        actions = {
            set_mode;
        }
        size = 1;
    }

    apply {
        tg_mode.apply();
        to_or_from_cpu.apply(hdr, ig_md, ig_intr_md, ig_tm_md);
        arp.apply(hdr, ig_md, ig_intr_md, ig_tm_md);
        p4tg.apply(hdr, ig_md, ig_intr_md, ig_prsr_md, ig_dprsr_md, ig_tm_md);
    }

}
