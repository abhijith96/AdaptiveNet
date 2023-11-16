# Copyright 2019-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# ------------------------------------------------------------------------------
# IPV6 ROUTING TESTS
#
# To run all tests:
#     make p4-test TEST=routing
#
# To run a specific test case:
#     make p4-test TEST=routing.<TEST CLASS NAME>
#
# For example:
#     make p4-test TEST=routing.IPv6RoutingTest
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
# Modify everywhere you see TODO
#
# When providing your solution, make sure to use the same names for P4Runtime
# entities as specified in your P4Info file.
#
# Test cases are based on the P4 program design suggested in the exercises
# README. Make sure to modify the test cases accordingly if you decide to
# implement the pipeline differently.
# ------------------------------------------------------------------------------

from ptf.testutils import group

from base_test import *

# header icmpv6_t {
#     bit<8>   type;
#     bit<8>   code;
#     bit<16>  checksum;
# }

# header ndp_t {
#     bit<32>      flags;
#     ipv6_addr_t  target_ipv6_addr;
#     // NDP option.
#     bit<8>       type;
#     bit<8>       length;
#     bit<48>      target_mac_addr;
# }


def genNdpNrPkt(target_ip, target_mac, eth_dst_mac = NDP_NR_MAC, src_mac=HOST1_MAC, src_ip=HOST1_IPV6):
    NDP_TARGET_VLA_ADDR = 3
    nsma = in6_getnsma(inet_pton(socket.AF_INET6, target_ip))
    d = inet_ntop(socket.AF_INET6, nsma)
    dm = in6_getnsmac(nsma)
    p = Ether(dst=eth_dst_mac) / IPv6(dst=d, src=src_ip, hlim=255)
    p /= ICMPv6ND_NR(tgt=target_ip)
    p /= ICMPv6NDNROptSrcLLAddr(lladdr=target_mac)
    return p

def genNdpNrReplyPkt(ipv6_source, ipv6_dst, target_ip, target_mac, eth_dst_mac, eth_src_mac):
    NDP_TARGET_VLA_ADDR = 3
    p = Ether(src= eth_src_mac,dst=eth_dst_mac) / IPv6(dst=ipv6_dst, src=ipv6_source, hlim=255)
    p /= ICMPv6ND_NRReply(tgt=target_ip)
    p /= ICMPv6NDNROptSrcLLAddr(lladdr=target_mac)
    return p



@group("routing")
class IPv6RoutingTest(P4RuntimeTest):
    """Tests basic IPv6 routing"""

    def runTest(self):
        # Test with different type of packets.
        for pkt_type in ["tcpv6", "udpv6", "icmpv6"]:
            print_inline("%s ... " % pkt_type)
            pkt = getattr(testutils, "simple_%s_packet" % pkt_type)()
            self.testPacket(pkt)

    @autocleanup
    def testPacket(self, pkt):
        next_hop_mac = SWITCH2_MAC

        # Add entry to "My Station" table. Consider the given pkt's eth dst addr
        # as myStationMac address.
        # *** TODO EXERCISE 5
        # Modify names to match content of P4Info file (look for the fully
        # qualified name of tables, match fields, and actions.
        # ---- START SOLUTION ----
        self.insert(self.helper.build_table_entry(
            table_name="IngressPipeImpl.my_station_table",
            match_fields={
                # Exact match.
                "hdr.ethernet.dst_addr": pkt[Ether].dst
            },
            action_name="NoAction"
        ))
        # ---- END SOLUTION ----

        # Insert ECMP group with only one member (next_hop_mac)
        # *** TODO EXERCISE 5
        # Modify names to match content of P4Info file (look for the fully
        # qualified name of tables, match fields, and actions.
        # ---- START SOLUTION ----
        self.insert(self.helper.build_act_prof_group(
            act_prof_name="IngressPipeImpl.ecmp_selector",
            group_id=1,
            actions=[
                # List of tuples (action name, action param dict)
                ("IngressPipeImpl.set_next_hop", {"next_hop_mac": next_hop_mac}),
            ]
        ))
        # ---- END SOLUTION ----

        # Insert L3 routing entry to map pkt's IPv6 dst addr to group
        # *** TODO EXERCISE 5
        # Modify names to match content of P4Info file (look for the fully
        # qualified name of tables, match fields, and actions.
        # ---- START SOLUTION ----
        self.insert(self.helper.build_table_entry(
            table_name="IngressPipeImpl.routing_v6_table",
            match_fields={
                # LPM match (value, prefix)
                "hdr.ipv6.dst_addr": (pkt[IPv6].dst, 128)
            },
            group_id=1
        ))
        # ---- END SOLUTION ----

        # Insert L3 entry to map next_hop_mac to output port 2.
        # *** TODO EXERCISE 5
        # Modify names to match content of P4Info file (look for the fully
        # qualified name of tables, match fields, and actions.
        # ---- START SOLUTION ----
        self.insert(self.helper.build_table_entry(
            table_name="IngressPipeImpl.l2_exact_table",
            match_fields={
                # Exact match
                "hdr.ethernet.dst_addr": next_hop_mac
            },
            action_name="IngressPipeImpl.set_egress_port",
            action_params={
                "port_num": self.port2
            }
        ))
        # ---- END SOLUTION ----

        # Expected pkt should have routed MAC addresses and decremented hop
        # limit (TTL).
        exp_pkt = pkt.copy()
        pkt_route(exp_pkt, next_hop_mac)
        pkt_decrement_ttl(exp_pkt)

        testutils.send_packet(self, self.port1, str(pkt))
        testutils.verify_packet(self, exp_pkt, self.port2)


@group("routing")
class NdpReplyGenTest(P4RuntimeTest):
    """Tests automatic generation of NDP Neighbor Advertisement for IPV6
    addresses associated to the switch interface.
    """

    @autocleanup
    def runTest(self):
        switch_ip = SWITCH1_IPV6
        target_mac = SWITCH1_MAC

        # Insert entry to transform NDP NA packets for the given target address
        # (match), to NDP NA packets with the given target MAC address (action
        # *** TODO EXERCISE 5
        # Modify names to match content of P4Info file (look for the fully
        # qualified name of tables, match fields, and actions.
        # ---- START SOLUTION ----
        self.insert(self.helper.build_table_entry(
            table_name="IngressPipeImpl.ndp_reply_table",
            match_fields={
                # Exact match.
                "hdr.ndp.target_ipv6_addr": switch_ip
            },
            action_name="IngressPipeImpl.ndp_ns_to_ndp_na",
            action_params={
                "target_mac": target_mac
            }
        ))
        # ---- END SOLUTION ----

        # NDP Neighbor Solicitation packet
        pkt = genNdpNsPkt(target_ip=switch_ip)

        # NDP Neighbor Advertisement packet
        exp_pkt = genNdpNaPkt(target_ip=switch_ip,
                              target_mac=target_mac,
                              src_mac=target_mac,
                              src_ip=switch_ip,
                              dst_ip=pkt[IPv6].src)

        # Send NDP NS, expect NDP NA from the same port.
        testutils.send_packet(self, self.port1, str(pkt))
        testutils.verify_packet(self, exp_pkt, self.port1)


    

@group("routing")
class NdpNameResolutionTest(P4RuntimeTest):
    """Tests automatic generation of NDP Neighbor Advertisement for IPV6
    addresses associated to the switch interface.
    """

    @autocleanup
    def runTest(self):
        switch_ip = SWITCH1_IPV6
        switch_mac = SWITCH1_MAC
        target_mac = HOST2_MAC

        host_2_vla_part_one = "0001:0001:0001:0001:1001:1003:1002:1003"
        host_2_vla_part_two = "0000:0009:1005:0000:0000:0000:0000:0000"
       

        # Insert entry to transform NDP NA packets for the given target address
        # (match), to NDP NA packets with the given target MAC address (action
        # *** TODO EXERCISE 5
        # Modify names to match content of P4Info file (look for the fully
        # qualified name of tables, match fields, and actions.
        # ---- START SOLUTION ----
        self.insert(self.helper.build_table_entry(
            table_name="IngressPipeImpl.ndp_name_resolution_table",
            match_fields={
                # Exact match.
                "hdr.ndp.target_mac_addr": target_mac
            },
            action_name="IngressPipeImpl.ndp_nr",
            action_params={
                "device_mac": switch_mac,
                "target_vla_part_one" : host_2_vla_part_one,
                "target_vla_part_two" : host_2_vla_part_two,
            }
        ))
        # ---- END SOLUTION ----

        # NDP Neighbor Solicitation packet
        pkt = genNdpNrPkt(target_ip=switch_ip, target_mac= target_mac)

        # NDP Neighbor Advertisement packet
        exp_pkt = genNdpNrReplyPkt(host_2_vla_part_one, host_2_vla_part_two, switch_ip, target_mac,
                                   HOST1_MAC, switch_mac)
        
        payload_data = exp_pkt.payload
        exp_pkt[IPv6].remove_payload()
        raw_packet = Ether(src = exp_pkt[Ether.src], dst = exp_pkt[Ether.src])/IPv6(src=host_2_vla_part_one, dst = 
        host_2_vla_part_two, nh = 58) / Raw(load=payload_data)

        # Send NDP NS, expect NDP NA from the same port.
        testutils.send_packet(self, self.port1, str(pkt))
        testutils.verify_packet(self, raw_packet, self.port1)