/*
 * Copyright 2019-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include <core.p4>
#include <v1model.p4>

// CPU_PORT specifies the P4 port number associated to controller packet-in and
// packet-out. All packets forwarded via this port will be delivered to the
// controller as P4Runtime PacketIn messages. Similarly, PacketOut messages from
// the controller will be seen by the P4 pipeline as coming from the CPU_PORT.
#define CPU_PORT 255

// CPU_CLONE_SESSION_ID specifies the mirroring session for packets to be cloned
// to the CPU port. Packets associated with this session ID will be cloned to
// the CPU_PORT as well as being transmitted via their egress port (set by the
// bridging/routing/acl table). For cloning to work, the P4Runtime controller
// needs first to insert a CloneSessionEntry that maps this session ID to the
// CPU_PORT.
#define CPU_CLONE_SESSION_ID 99

// Maximum number of hops supported when using SRv6.
// Required for Exercise 7.
#define SRV6_MAX_HOPS 4

// #define VLA_MAX_LEVELS 10

const bit<8> VLA_MAX_LEVELS = 10;

typedef bit<9>   port_num_t;
typedef bit<48>  mac_addr_t;
typedef bit<16>  mcast_group_id_t;
typedef bit<32>  ipv4_addr_t;
typedef bit<128> ipv6_addr_t;
typedef bit<16>  l4_port_t;

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_IPV6 = 0x86dd;

const bit<8> IP_PROTO_ICMP   = 1;
const bit<8> IP_PROTO_TCP    = 6;
const bit<8> IP_PROTO_UDP    = 17;
const bit<8> IP_PROTO_SRV6   = 43;
const bit<8> IP_PROTO_VLA   = 48;
const bit<8> IP_PROTO_ICMPV6 = 58;

const mac_addr_t IPV6_MCAST_01 = 0x33_33_00_00_00_01;

const bit<8> ICMP6_TYPE_NS = 135;
const bit<8> ICMP6_TYPE_NA = 136;
const bit<8> ICMP6_TYPE_ND = 200;
const bit<8> ICMP6_TYPE_ND_REPLY = 201;

const bit<8> NDP_OPT_TARGET_LL_ADDR = 2;

const bit<8> NDP_TARGET_VLA_ADDR = 3;
const bit<8> NDP_TARGET_VLA_ADDR_NOT_FOUND = 4;

const bit<32> NDP_FLAG_ROUTER    = 0x80000000;
const bit<32> NDP_FLAG_SOLICITED = 0x40000000;
const bit<32> NDP_FLAG_OVERRIDE  = 0x20000000;
const bit<32> NDP_FLAG_NAME_RESOLUTION  = 0x10000000;


//------------------------------------------------------------------------------
// HEADER DEFINITIONS
//------------------------------------------------------------------------------

header ethernet_t {
    mac_addr_t  dst_addr;
    mac_addr_t  src_addr;
    bit<16>     ether_type;
}

header ipv4_t {
    bit<4>   version;
    bit<4>   ihl;
    bit<6>   dscp;
    bit<2>   ecn;
    bit<16>  total_len;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdr_checksum;
    bit<32>  src_addr;
    bit<32>  dst_addr;
}

header ipv6_t {
    bit<4>    version;
    bit<8>    traffic_class;
    bit<20>   flow_label;
    bit<16>   payload_len;
    bit<8>    next_hdr;
    bit<8>    hop_limit;
    bit<128>  src_addr;
    bit<128>  dst_addr;
}

header vlah_t {
    bit<8> next_hdr;
    bit<8> hdr_ext_len;
    bit<2> address_type;
    bit<16> current_level;
    bit<16> num_levels;
    bit<16> num_source_levels;
    bit<6> _pad;
}

header vla_list_t{
    bit<16> level_id;
}

header vla_padding_t{
    varbit<128> tlv_objects;
}
header srv6h_t {
    bit<8>   next_hdr;
    bit<8>   hdr_ext_len;
    bit<8>   routing_type;
    bit<8>   segment_left;
    bit<8>   last_entry;
    bit<8>   flags;
    bit<16>  tag;
}

header srv6_list_t {
    bit<128>  segment_id;
}

header tcp_t {
    bit<16>  src_port;
    bit<16>  dst_port;
    bit<32>  seq_no;
    bit<32>  ack_no;
    bit<4>   data_offset;
    bit<3>   res;
    bit<3>   ecn;
    bit<6>   ctrl;
    bit<16>  window;
    bit<16>  checksum;
    bit<16>  urgent_ptr;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> len;
    bit<16> checksum;
}

header icmp_t {
    bit<8>   type;
    bit<8>   icmp_code;
    bit<16>  checksum;
    bit<16>  identifier;
    bit<16>  sequence_number;
    bit<64>  timestamp;
}

header icmpv6_t {
    bit<8>   type;
    bit<8>   code;
    bit<16>  checksum;
}

header ndp_t {
    bit<32>      flags;
    ipv6_addr_t  target_ipv6_addr;
    // NDP option.
    bit<8>       type;
    bit<8>       length;
    bit<48>      target_mac_addr;
}

// Packet-in header. Prepended to packets sent to the CPU_PORT and used by the
// P4Runtime server (Stratum) to populate the PacketIn message metadata fields.
// Here we use it to carry the original ingress port where the packet was
// received.
@controller_header("packet_in")
header cpu_in_header_t {
    port_num_t  ingress_port;
    bit<7>      _pad;
}

// Packet-out header. Prepended to packets received from the CPU_PORT. Fields of
// this header are populated by the P4Runtime server based on the P4Runtime
// PacketOut metadata fields. Here we use it to inform the P4 pipeline on which
// port this packet-out should be transmitted.
@controller_header("packet_out")
header cpu_out_header_t {
    port_num_t  egress_port;
    bit<7>      _pad;
}

struct parsed_headers_t {
    cpu_out_header_t cpu_out;
    cpu_in_header_t cpu_in;
    ethernet_t ethernet;
    ipv4_t ipv4;
    ipv6_t ipv6;
    vlah_t vlah;
    vla_list_t[VLA_MAX_LEVELS] vla_list;
    vla_list_t[VLA_MAX_LEVELS] vla_source_list;
    vla_padding_t vla_padding;
    srv6h_t srv6h;
    srv6_list_t[SRV6_MAX_HOPS] srv6_list;
    tcp_t tcp;
    udp_t udp;
    icmp_t icmp;
    icmpv6_t icmpv6;
    ndp_t ndp;
}

struct parser_local_metadata_t{
     bit<32> active_level_index;
     bit<16> active_level_value;
     bit<32> active_source_level_index;
     bool is_first_vla_level;
     bit<160> destination_address_key;
     bit<32> vla_fixed_length_in_bits;
}

struct local_metadata_t {
    parser_local_metadata_t parser_local_metadata;
    l4_port_t   l4_src_port;
    l4_port_t   l4_dst_port;
    bool        is_multicast;
    bool is_current_vla_marked;
    bit<16> vla_previous_level_value;
    bit<16> vla_current_level_value;
    bit<16> vla_next_level_value;
    bit<32> current_level_index;
    ipv6_addr_t next_srv6_sid;
    bit<8>      ip_proto;
    bit<8>      icmp_type;
}


//------------------------------------------------------------------------------
// INGRESS PIPELINE
//------------------------------------------------------------------------------


parser ParserImpl (packet_in packet,
                   out parsed_headers_t hdr,
                   inout local_metadata_t local_metadata,
                   inout standard_metadata_t standard_metadata)
{

    state start {
        transition select(standard_metadata.ingress_port) {
            CPU_PORT: parse_packet_out;
            default: parse_ethernet;
        }
    }

    state parse_packet_out {
        packet.extract(hdr.cpu_out);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type){
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        local_metadata.ip_proto = hdr.ipv4.protocol;
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            IP_PROTO_ICMP: parse_icmp;
            default: accept;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        local_metadata.ip_proto = hdr.ipv6.next_hdr;
        transition select(hdr.ipv6.next_hdr) {
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            IP_PROTO_ICMPV6: parse_icmpv6;
            IP_PROTO_SRV6: parse_srv6;
            IP_PROTO_VLA : parse_vlah;
            default: accept;
        }
        
    }

    state parse_vlah{
        packet.extract(hdr.vlah);
        local_metadata.parser_local_metadata.is_first_vla_level = true;
        local_metadata.parser_local_metadata.destination_address_key = 0;
        local_metadata.ip_proto = hdr.vlah.next_hdr;
        transition parse_vla_list;
    }

    state parse_vla_list {
        packet.extract(hdr.vla_list.next);
        bit<32> current_level_index  = (bit<32>)hdr.vla_list.lastIndex + 1;
        local_metadata.parser_local_metadata.active_level_index = current_level_index;
        local_metadata.parser_local_metadata.active_level_value = hdr.vla_list.last.level_id;
        bool is_current_level_first = local_metadata.parser_local_metadata.is_first_vla_level;
        transition skip_if_current_level_marked;
    }

    state skip_if_current_level_marked{
        transition select (local_metadata.is_current_vla_marked){
            true: iterate_vla_again;
            default: compute_address;
        }
    }

    state compute_address {
        bool is_current_level_first = local_metadata.parser_local_metadata.is_first_vla_level;
        transition select(is_current_level_first) {
            true: update_destination_address;
            default: shift_destination_address;
        }
    }

    state shift_destination_address{
        local_metadata.parser_local_metadata.destination_address_key =  local_metadata.parser_local_metadata.destination_address_key << 16;
        transition update_destination_address;
    }

    state update_destination_address{
        local_metadata.parser_local_metadata.is_first_vla_level = false;
        local_metadata.parser_local_metadata.destination_address_key = local_metadata.parser_local_metadata.destination_address_key + (bit<160>)local_metadata.parser_local_metadata.active_level_value;
        transition parse_vla_list_remains;
    }

    state parse_vla_list_remains {
        bool is_list_val_current_level_index = local_metadata.parser_local_metadata.active_level_index == (bit<32>)hdr.vlah.current_level;
        transition select(is_list_val_current_level_index) {
            true: mark_current_vla;
            default: iterate_vla_again;
        }
    }

    state mark_current_vla{
        local_metadata.vla_current_level_value = hdr.vla_list.last.level_id;
        bool last_segment = (bit<32>)hdr.vlah.num_levels == (bit<32>)(hdr.vla_list.lastIndex + 1);
        local_metadata.is_current_vla_marked = true;
        transition select(last_segment){
            true: parse_vla_source_list;
            default :vla_extract_next_hdr;
        }
    }

    state vla_extract_next_hdr{
        packet.extract(hdr.vla_list.next);
        local_metadata.vla_next_level_value = hdr.vla_list.last.level_id;
        transition iterate_vla_again;
    }

    state iterate_vla_again{
        local_metadata.vla_previous_level_value = hdr.vla_list.last.level_id;
        bool last_segment = (bit<32>)hdr.vlah.num_levels == (bit<32>)(hdr.vla_list.lastIndex + 1);
        transition select(last_segment) {
           true: parse_vla_source_list;
           default: parse_vla_list;
        }

    }

    state parse_vla_source_list{
        packet.extract(hdr.vla_source_list.next);
        local_metadata.parser_local_metadata.active_source_level_index = hdr.vla_source_list.lastIndex + 1;
        transition iterate_vla_source_list_again;
    }

    state iterate_vla_source_list_again{

        bool last_level = (bit<32>)hdr.vlah.num_source_levels == (bit<32>)(local_metadata.parser_local_metadata.active_source_level_index);
        transition select(last_level) {
            true: parse_vla_next_hdr;
            default: parse_vla_source_list;
        }   

    }

    state parse_vla_next_hdr{
        bit<32> vla_total_length = (((bit<32>)hdr.vlah.hdr_ext_len) *64) + 64;
        local_metadata.parser_local_metadata.vla_fixed_length_in_bits = vla_total_length;
        bit<32> vla_fixed_length = 64 + 8 + ((bit<32>)(hdr.vlah.num_source_levels  + hdr.vlah.num_levels)* 16);
        bit<32> padding_length = vla_total_length - vla_fixed_length;
        packet.extract(hdr.vla_padding, padding_length);
       transition select(hdr.vlah.next_hdr) {
            IP_PROTO_SRV6 : parse_srv6;
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            IP_PROTO_ICMPV6: parse_icmpv6;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        local_metadata.l4_src_port = hdr.tcp.src_port;
        local_metadata.l4_dst_port = hdr.tcp.dst_port;
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        local_metadata.l4_src_port = hdr.udp.src_port;
        local_metadata.l4_dst_port = hdr.udp.dst_port;
        transition accept;
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        local_metadata.icmp_type = hdr.icmp.type;
        transition accept;
    }

    state parse_icmpv6 {
        packet.extract(hdr.icmpv6);
        local_metadata.icmp_type = hdr.icmpv6.type;
        transition select(hdr.icmpv6.type) {
            ICMP6_TYPE_NS: parse_ndp;
            ICMP6_TYPE_NA: parse_ndp;
            ICMP6_TYPE_ND: parse_ndp;
            default: accept;
        }
    }

    state parse_ndp {
        packet.extract(hdr.ndp);
        transition accept;
    }

    state parse_srv6 {
        packet.extract(hdr.srv6h);
        transition parse_srv6_list;
    }

    state parse_srv6_list {
        packet.extract(hdr.srv6_list.next);
        bool next_segment = (bit<32>)hdr.srv6h.segment_left - 1 == (bit<32>)hdr.srv6_list.lastIndex;
        transition select(next_segment) {
            true: mark_current_srv6;
            default: check_last_srv6;
        }
    }

    state mark_current_srv6 {
        local_metadata.next_srv6_sid = hdr.srv6_list.last.segment_id;
        transition check_last_srv6;
    }

    state check_last_srv6 {
        // working with bit<8> and int<32> which cannot be cast directly; using
        // bit<32> as common intermediate type for comparision
        bool last_segment = (bit<32>)hdr.srv6h.last_entry == (bit<32>)hdr.srv6_list.lastIndex;
        transition select(last_segment) {
           true: parse_srv6_next_hdr;
           false: parse_srv6_list;
        }
    }

    state parse_srv6_next_hdr {
        transition select(hdr.srv6h.next_hdr) {
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            IP_PROTO_ICMPV6: parse_icmpv6;
            default: accept;
        }
    }
}


control VerifyChecksumImpl(inout parsed_headers_t hdr,
                           inout local_metadata_t meta)
{
    // Not used here. We assume all packets have valid checksum, if not, we let
    // the end hosts detect errors.
    apply { /* EMPTY */ }
}


control IngressPipeImpl (inout parsed_headers_t    hdr,
                         inout local_metadata_t    local_metadata,
                         inout standard_metadata_t standard_metadata) {

    // Drop action shared by many tables.
    action drop() {
        mark_to_drop(standard_metadata);
    }


    // *** L2 BRIDGING
    //
    // Here we define tables to forward packets based on their Ethernet
    // destination address. There are two types of L2 entries that we
    // need to support:
    //
    // 1. Unicast entries: which will be filled in by the control plane when the
    //    location (port) of new hosts is learned.
    // 2. Broadcast/multicast entries: used replicate NDP Neighbor Solicitation
    //    (NS) messages to all host-facing ports;
    //
    // For (2), unlike ARP messages in IPv4 which are broadcasted to Ethernet
    // destination address FF:FF:FF:FF:FF:FF, NDP messages are sent to special
    // Ethernet addresses specified by RFC2464. These addresses are prefixed
    // with 33:33 and the last four octets are the last four octets of the IPv6
    // destination multicast address. The most straightforward way of matching
    // on such IPv6 broadcast/multicast packets, without digging in the details
    // of RFC2464, is to use a ternary match on 33:33:**:**:**:**, where * means
    // "don't care".
    //
    // For this reason, our solution defines two tables. One that matches in an
    // exact fashion (easier to scale on switch ASIC memory) and one that uses
    // ternary matching (which requires more expensive TCAM memories, usually
    // much smaller).

    // --- l2_exact_table (for unicast entries) --------------------------------

    action set_egress_port(port_num_t port_num) {
        standard_metadata.egress_spec = port_num;
    }

    table l2_exact_table {
        key = {
            hdr.ethernet.dst_addr: exact;
        }
        actions = {
            set_egress_port;
            @defaultonly drop;
        }
        const default_action = drop;
        // The @name annotation is used here to provide a name to this table
        // counter, as it will be needed by the compiler to generate the
        // corresponding P4Info entity.
        @name("l2_exact_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }

    // --- l2_ternary_table (for broadcast/multicast entries) ------------------

    action set_multicast_group(mcast_group_id_t gid) {
        // gid will be used by the Packet Replication Engine (PRE) in the
        // Traffic Manager--located right after the ingress pipeline, to
        // replicate a packet to multiple egress ports, specified by the control
        // plane by means of P4Runtime MulticastGroupEntry messages.
        standard_metadata.mcast_grp = gid;
        local_metadata.is_multicast = true;
    }

    table l2_ternary_table {
        key = {
            hdr.ethernet.dst_addr: ternary;
        }
        actions = {
            set_multicast_group;
            @defaultonly drop;
        }
        const default_action = drop;
        @name("l2_ternary_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }


    // *** TODO EXERCISE 5 (IPV6 ROUTING)
    //
    // 1. Create a table to to handle NDP messages to resolve the MAC address of
    //    switch. This table should:
    //    - match on hdr.ndp.target_ipv6_addr (exact match)
    //    - provide action "ndp_ns_to_na" (look in snippets.p4)
    //    - default_action should be "NoAction"
    //
    action ndp_ns_to_ndp_na (mac_addr_t target_mac){
            hdr.ethernet.src_addr = target_mac;
            hdr.ethernet.dst_addr = IPV6_MCAST_01;
            ipv6_addr_t host_ipv6_tmp = hdr.ipv6.src_addr;
            hdr.ipv6.src_addr = hdr.ndp.target_ipv6_addr;
            hdr.ipv6.dst_addr = host_ipv6_tmp;
            hdr.ipv6.next_hdr = IP_PROTO_ICMPV6;
            hdr.icmpv6.type = ICMP6_TYPE_NA;
            hdr.ndp.flags = NDP_FLAG_ROUTER | NDP_FLAG_OVERRIDE;
            hdr.ndp.type = NDP_OPT_TARGET_LL_ADDR;
            hdr.ndp.length = 1;
            hdr.ndp.target_mac_addr = target_mac;
            standard_metadata.egress_spec = standard_metadata.ingress_port;
    }
    table ndp_reply_table{
        key = {
            hdr.ndp.target_ipv6_addr : exact;
        }
        actions = {
            ndp_ns_to_ndp_na;
        }
        @name("ndp_reply_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }


        /**
           This action maps the mac address of any host in network with its vla address encoded in two fields,
           target_vla_part_one containing first 128 bits,
           target vla_part_two containing first 32 bits as number of levels and next 32 bits as remaning 32 bits of the 
           160 bit vla address.
           HostName is not supported by the onos host provider service, if so mac adddrss can be replaced with host name of the host

        **/
    action ndp_nr (bit<128> target_vla_part_one, bit<48> target_vla_part_two, mac_addr_t device_mac){
        hdr.ethernet.src_addr = device_mac;
        hdr.ethernet.dst_addr = IPV6_MCAST_01;
        // hdr.ipv6.src_addr = target_vla_part_one;
        // hdr.ipv6.dst_addr = target_vla_part_two;
        ipv6_addr_t host_ipv6_tmp = hdr.ipv6.src_addr;
        hdr.ipv6.src_addr = target_vla_part_one;
        hdr.ipv6.dst_addr = host_ipv6_tmp;
        hdr.ipv6.next_hdr = IP_PROTO_ICMPV6;
        hdr.icmpv6.type = ICMP6_TYPE_NA;
        //hdr.ndp.target_ipv6_addr = target_vla_part_two;
        hdr.ndp.flags = NDP_FLAG_ROUTER | NDP_FLAG_NAME_RESOLUTION;
        hdr.ndp.type = NDP_TARGET_VLA_ADDR;
        hdr.ndp.length = 1;
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    table ndp_name_resolution_table{
        key = {
            hdr.ndp.target_mac_addr : exact;
        }
        actions = {
            ndp_nr;
        }
    @name("ndp_name_resolution_table_counter")
    counters = direct_counter(CounterType.packets_and_bytes);
    }
    // 2. Create table to handle IPv6 routing. Create a L2 my station table (hit
    //    when Ethernet destination address is the switch address). This table
    //    should not do anything to the packet (i.e., NoAction), but the control
    //    block below should use the result (table.hit) to decide how to process
    //    the packet.
    //

    table my_station_table {
        key = {
            hdr.ethernet.dst_addr : exact;
        }
        actions = {
            NoAction;
        }
        @name("my_station_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }



    // 3. Create a table for IPv6 routing. An action selector should be use to
    //    pick a next hop MAC address according to a hash of packet header
    //    fields (IPv6 source/destination address and the flow label). Look in
    //    snippets.p4 for an example of an action selector and table using it.
    //
    // You can name your tables whatever you like. You will need to fill
    // the name in elsewhere in this exercise.
    action_selector(HashAlgorithm.crc16, 32w1024, 32w16) ecmp_selector;

        action set_next_hop(mac_addr_t next_hop_mac){
            hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
            hdr.ethernet.dst_addr = next_hop_mac;
            hdr.ipv6.hop_limit = hdr.ipv6.hop_limit - 1;
        }

        table routing_v6_table{
            key = {
              hdr.ipv6.dst_addr : lpm;
              hdr.ipv6.dst_addr:          selector;
              hdr.ipv6.src_addr:          selector;
              hdr.ipv6.flow_label:        selector;
              // The rest of the 5-tuple is optional per RFC6438
              hdr.ipv6.next_hdr:          selector;
              local_metadata.l4_src_port: selector;
              local_metadata.l4_dst_port: selector;
            }
            actions = {
                set_next_hop;
            }
            implementation = ecmp_selector;
            @name("routing_v6_table_counter")
            counters = direct_counter(CounterType.packets_and_bytes);
        }



    // *** TODO EXERCISE 6 (SRV6)
    //
    // Implement tables to provide SRV6 logic.

    action srv6_end(){
        hdr.srv6h.segment_left = hdr.srv6h.segment_left - 1;
        hdr.ipv6.dst_addr = local_metadata.next_srv6_sid;
    }

    table srv6_my_sid {
        key = {
            hdr.ipv6.dst_addr : lpm;
        }
        actions = {
            srv6_end;
        }
        @name("srv6_my_sid_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);

    }

    action insert_srv6h_header(bit<8> num_segments) {
        hdr.srv6h.setValid();
        hdr.srv6h.next_hdr = hdr.ipv6.next_hdr;
        hdr.srv6h.hdr_ext_len =  num_segments * 2;
        hdr.srv6h.routing_type = 4;
        hdr.srv6h.segment_left = num_segments - 1;
        hdr.srv6h.last_entry = num_segments - 1;
        hdr.srv6h.flags = 0;
        hdr.srv6h.tag = 0;
        hdr.ipv6.next_hdr = IP_PROTO_SRV6;
    }

    action srv6_t_insert_2(ipv6_addr_t s1, ipv6_addr_t s2) {
        hdr.ipv6.dst_addr = s1;
        hdr.ipv6.payload_len = hdr.ipv6.payload_len + 40;
        insert_srv6h_header(2);
        hdr.srv6_list[0].setValid();
        hdr.srv6_list[0].segment_id = s2;
        hdr.srv6_list[1].setValid();
        hdr.srv6_list[1].segment_id = s1;
    }

    action srv6_t_insert_3(ipv6_addr_t s1, ipv6_addr_t s2, ipv6_addr_t s3) {
        hdr.ipv6.dst_addr = s1;
        hdr.ipv6.payload_len = hdr.ipv6.payload_len + 56;
        insert_srv6h_header(3);
        hdr.srv6_list[0].setValid();
        hdr.srv6_list[0].segment_id = s3;
        hdr.srv6_list[1].setValid();
        hdr.srv6_list[1].segment_id = s2;
        hdr.srv6_list[2].setValid();
        hdr.srv6_list[2].segment_id = s1;
    }

    table srv6_transit {
      key = {

            hdr.ipv6.dst_addr : lpm;
          // TODO: Add match fields for SRv6 transit rules; we'll start with the
          //  destination IP address.
      }
      actions = {
          // Note: Single segment header doesn't make sense given PSP
          // i.e. we will pop the SRv6 header when segments_left reaches 0
          srv6_t_insert_2;
          srv6_t_insert_3;
          // Extra credit: set a metadata field, then push label stack in egress
      }
      @name("srv6_transit_table_counter")
      counters = direct_counter(CounterType.packets_and_bytes);
    }

    action srv6_pop() {
      hdr.ipv6.next_hdr = hdr.srv6h.next_hdr;
      // SRv6 header is 8 bytes
      // SRv6 list entry is 16 bytes each
      // (((bit<16>)hdr.srv6h.last_entry + 1) * 16) + 8;
      bit<16> srv6h_size = (((bit<16>)hdr.srv6h.last_entry + 1) << 4) + 8;
      hdr.ipv6.payload_len = hdr.ipv6.payload_len - srv6h_size;

      hdr.srv6h.setInvalid();
      // Need to set MAX_HOPS headers invalid
      hdr.srv6_list[0].setInvalid();
      hdr.srv6_list[1].setInvalid();
      hdr.srv6_list[2].setInvalid();
    }

    // ****VLA TABLES//

    table vla_level_table {
        key = 
        { 
            hdr.vlah.current_level : exact;
        
        }
        actions = {
            NoAction;
        }
        @name("vla_level_table_counter")
      counters = direct_counter(CounterType.packets_and_bytes);
    }

    // table vla_level_value_table {
    //     key = {
    //         local_metadata.vla_current_level_value : exact;
    //     }
    //     actions = {
    //         NoAction;
    //     }
    //     @name("vla_level_value_counter")
    //     counters = direct_counter(CounterType.packets_and_bytes);
    // }

    // action vla_set_level_value (bit<16> level_value) {
    //     local_metadata.parser_local_metadata.active_level_value = level_value;
    // }
    // table vla_level_to_level_value_table {
    //     key = {
    //         local_metadata.parser_local_metadata.active_level_index : exact;
    //     }
    //     actions = {
    //         vla_set_level_value;
    //     }
    //     @name("vla_level_to_level_value_table_counter")
    //     counters = direct_counter(CounterType.packets_and_bytes);
    // }

    table current_vla_address_table {
        key = {
            local_metadata.parser_local_metadata.destination_address_key : exact;
        }
        actions = {
            NoAction;
        }
        @name("current_vla_address_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }

    action vla_route_to_child (mac_addr_t target_mac){
        hdr.vlah.current_level = hdr.vlah.current_level + 1;
        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = target_mac;
    }

    table vla_route_children_table {
        key = {
            local_metadata.vla_next_level_value : exact;
        }
        actions = {
            vla_route_to_child;
        }
        @name("vla_route_children_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }

    action vla_route_to_parent (mac_addr_t target_mac){
        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = target_mac;
        hdr.vlah.current_level = hdr.vlah.current_level - 1;
    }

    table vla_route_to_parent_table{
        key = 
        { 
            hdr.vlah.current_level : exact;

        }
        actions = {
            vla_route_to_parent;
          
        }
        @name("vla_route_to_parent_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }

    // *** ACL
    //
    // Provides ways to override a previous forwarding decision, for example
    // requiring that a packet is cloned/sent to the CPU, or dropped.
    //
    // We use this table to clone all NDP packets to the control plane, so to
    // enable host discovery. When the location of a new host is discovered, the
    // controller is expected to update the L2 and L3 tables with the
    // corresponding bridging and routing entries.

    action send_to_cpu() {
        standard_metadata.egress_spec = CPU_PORT;
    }

    action clone_to_cpu() {
        // Cloning is achieved by using a v1model-specific primitive. Here we
        // set the type of clone operation (ingress-to-egress pipeline), the
        // clone session ID (the CPU one), and the metadata fields we want to
        // preserve for the cloned packet replica.
        clone3(CloneType.I2E, CPU_CLONE_SESSION_ID, { standard_metadata.ingress_port });
    }

    table acl_table {
        key = {
            standard_metadata.ingress_port: ternary;
            hdr.ethernet.dst_addr:          ternary;
            hdr.ethernet.src_addr:          ternary;
            hdr.ethernet.ether_type:        ternary;
            local_metadata.ip_proto:        ternary;
            local_metadata.icmp_type:       ternary;
            local_metadata.l4_src_port:     ternary;
            local_metadata.l4_dst_port:     ternary;
        }
        actions = {
            send_to_cpu;
            clone_to_cpu;
            drop;
        }
        @name("acl_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }

    apply {

        if (hdr.cpu_out.isValid()) {
            // *** TODO EXERCISE 4
            // Implement logic such that if this is a packet-out from the
            // controller:
            // 1. Set the packet egress port to that found in the cpu_out header
            // 2. Remove (set invalid) the cpu_out header
            // 3. Exit the pipeline here (no need to go through other tables
            standard_metadata.egress_spec = hdr.cpu_out.egress_port;
            hdr.cpu_out.setInvalid();
            exit;
        }

        bool do_l3_l2 = true;

        if (hdr.icmpv6.isValid()) {
           
            // Insert logic to handle NDP messages to resolve the MAC address of the
            // switch. You should apply the NDP reply table created before.
            // If this is an NDP NS packet, i.e., if a matching entry is found,
            // unset the "do_l3_l2" flag to skip the L3 and L2 tables, as the
            // "ndp_ns_to_na" action already set an egress port.

            if(hdr.icmpv6.type == ICMP6_TYPE_NS){
                if(ndp_reply_table.apply().hit){
                    do_l3_l2 = false;
                }
            }
            else if(hdr.icmpv6.type == ICMP6_TYPE_ND){
                if(ndp_name_resolution_table.apply().hit){
                     do_l3_l2 = false;
                }
                else
                {
                    do_l3_l2 = false;
                    local_metadata.is_multicast = false;
                    mac_addr_t src_host = hdr.ethernet.src_addr;
                    hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
                    hdr.ethernet.dst_addr = IPV6_MCAST_01;
                    hdr.ipv6.next_hdr = IP_PROTO_ICMPV6;
                    hdr.ipv6.dst_addr = hdr.ipv6.src_addr;
                    hdr.ipv6.src_addr = hdr.ndp.target_ipv6_addr;
                    hdr.icmpv6.type = ICMP6_TYPE_NA;
                    hdr.ndp.flags = NDP_FLAG_ROUTER;
                    hdr.ndp.type = NDP_TARGET_VLA_ADDR_NOT_FOUND;
                    hdr.ndp.length = 1;
                    standard_metadata.egress_spec = standard_metadata.ingress_port;
                    // mac_addr_t target_mac = 0x00aa00000001;
                    //  hdr.ethernet.src_addr = target_mac;
                    // hdr.ethernet.dst_addr = IPV6_MCAST_01;
                    // ipv6_addr_t host_ipv6_tmp = hdr.ipv6.src_addr;
                    // hdr.ipv6.src_addr = hdr.ndp.target_ipv6_addr;
                    // hdr.ipv6.dst_addr = host_ipv6_tmp;
                    // hdr.ipv6.next_hdr = IP_PROTO_ICMPV6;
                    // hdr.icmpv6.type = ICMP6_TYPE_NA;
                    // hdr.ndp.flags = NDP_FLAG_ROUTER | NDP_FLAG_OVERRIDE;
                    // hdr.ndp.type = NDP_OPT_TARGET_LL_ADDR;
                    // hdr.ndp.length = 1;
                    // hdr.ndp.target_mac_addr = target_mac;
                    // standard_metadata.egress_spec = standard_metadata.ingress_port;
                }
            }
        }

        if (do_l3_l2) {

            // *** TODO EXERCISE 5
            // Insert logic to match the My Station table and upon hit, the
            // routing table. You should also add a conditional to drop the
            // packet if the hop_limit reaches 0.

            if(hdr.ipv6.isValid() && my_station_table.apply().hit){

                if(hdr.vlah.isValid()){
                    bit<8> shift_count = (bit<8>)((VLA_MAX_LEVELS- (bit<8>)(hdr.vlah.current_level)) *16);
                    local_metadata.parser_local_metadata.destination_address_key = 
                    local_metadata.parser_local_metadata.destination_address_key << shift_count;
                    
                   
                     //add condition to drop if packet current level and level of switch does not match.
                    if(vla_level_table.apply().hit){
                        if(hdr.vlah.current_level > hdr.vlah.num_levels){
                            vla_route_to_parent_table.apply();
                        }
                        else if(!current_vla_address_table.apply().hit){
                            vla_route_to_parent_table.apply();
                        }
                        else if (hdr.vlah.num_levels > hdr.vlah.current_level){
                            vla_route_children_table.apply();
                        }
                        else{
                            drop();
                        }
                    }
                    else{
                        drop();
                    }
                }
                else {
                
                    if (srv6_my_sid.apply().hit) {
                    // PSP logic -- enabled for all packets
                        if (hdr.srv6h.isValid() && hdr.srv6h.segment_left == 0) {
                            srv6_pop();
                        }
                    }
                    else {
                        srv6_transit.apply();
                    }
                    routing_v6_table.apply();
                    if(hdr.ipv6.hop_limit == 0){
                        drop();
                    }
                }
               
               
            }



            // L2 bridging logic. Apply the exact table first...
            if (!l2_exact_table.apply().hit) {
                // ...if an entry is NOT found, apply the ternary one in case
                // this is a multicast/broadcast NDP NS packet.
                l2_ternary_table.apply();
            }
        }

        // Lastly, apply the ACL table.
        acl_table.apply();
    }
}


control EgressPipeImpl (inout parsed_headers_t hdr,
                        inout local_metadata_t local_metadata,
                        inout standard_metadata_t standard_metadata) {
    apply {

        if (standard_metadata.egress_port == CPU_PORT) {
            // *** TODO EXERCISE 4
            // Implement logic such that if the packet is to be forwarded to the
            // CPU port, e.g., if in ingress we matched on the ACL table with
            // action send/clone_to_cpu...
            // 1. Set cpu_in header as valid
            // 2. Set the cpu_in.ingress_port field to the original packet's
            //    ingress port (standard_metadata.ingress_port).
            hdr.cpu_in.setValid();
            hdr.cpu_in.ingress_port = standard_metadata.ingress_port;
        }

        // If this is a multicast packet (flag set by l2_ternary_table), make
        // sure we are not replicating the packet on the same port where it was
        // received. This is useful to avoid broadcasting NDP requests on the
        // ingress port.
        if (local_metadata.is_multicast == true &&
              standard_metadata.ingress_port == standard_metadata.egress_port) {
            mark_to_drop(standard_metadata);
        }
    }
}


control ComputeChecksumImpl(inout parsed_headers_t hdr,
                            inout local_metadata_t local_metadata)
{
    apply {
        // The following is used to update the ICMPv6 checksum of NDP
        // NA packets generated by the ndp reply table in the ingress pipeline.
        // This function is executed only if the NDP header is present.
        update_checksum(hdr.ndp.isValid(),
            {
                hdr.ipv6.src_addr,
                hdr.ipv6.dst_addr,
                hdr.ipv6.payload_len,
                8w0,
                hdr.ipv6.next_hdr,
                hdr.icmpv6.type,
                hdr.icmpv6.code,
                hdr.ndp.flags,
                hdr.ndp.target_ipv6_addr,
                hdr.ndp.type,
                hdr.ndp.length,
                hdr.ndp.target_mac_addr
            },
            hdr.icmpv6.checksum,
            HashAlgorithm.csum16
        );
    }
}


control DeparserImpl(packet_out packet, in parsed_headers_t hdr) {
    apply {
        packet.emit(hdr.cpu_in);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.vlah);
        packet.emit(hdr.vla_list);
        packet.emit(hdr.vla_source_list);
        packet.emit(hdr.vla_padding);
        packet.emit(hdr.srv6h);
        packet.emit(hdr.srv6_list);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.icmp);
        packet.emit(hdr.icmpv6);
        packet.emit(hdr.ndp);
    }
}


V1Switch(
    ParserImpl(),
    VerifyChecksumImpl(),
    IngressPipeImpl(),
    EgressPipeImpl(),
    ComputeChecksumImpl(),
    DeparserImpl()
) main;
