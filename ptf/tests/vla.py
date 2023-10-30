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
# VLA TESTS
#
# To run all tests:
#     make p4-test TEST=vla
#
# To run a specific test case:
#     make p4-test TEST=vla.<TEST CLASS NAME>
#
# For example:
#     make p4-test TEST=vla.Srv6InsertTest
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

from IPv6ExtHdrVLA import IPv6ExtHdrVLA




def insert_vla_header(pkt, sid_list, current_level_param):
    """Applies SRv6 insert transformation to the given packet.
    """
    # Set IPv6 dst to first SID...
    pkt[IPv6].dst = HOST2_IPV6
    # Insert SRv6 header between IPv6 header and payload
    sid_len = len(sid_list)
    srv6_hdr = IPv6ExtHdrVLA(
        nh=pkt[IPv6].nh,
        addresses=sid_list,
        len=(sid_len * 2) - 1,
        address_type = 0b01,
        current_level = current_level_param,
        number_of_levels= sid_len
        )
    pkt[IPv6].nh = 48  # next IPv6 header is SR header
    pkt[IPv6].payload = srv6_hdr / pkt[IPv6].payload
    return pkt


def pop_srv6_header(pkt):
    """Removes SRv6 header from the given packet.
    """
    pkt[IPv6].nh = pkt[IPv6ExtHdrVLA].nh
    pkt[IPv6].payload = pkt[IPv6ExtHdrVLA].payload


def set_cksum(pkt, cksum):
    if TCP in pkt:
        pkt[TCP].chksum = cksum
    if UDP in pkt:
        pkt[UDP].chksum = cksum
    if ICMPv6Unknown in pkt:
        pkt[ICMPv6Unknown].cksum = cksum


@group("vla")
class VlaRouteUpwards(P4RuntimeTest):
    """Tests Vla Behaviour, When Vla Address has less levels than level of current switch, it should forward packet to parent
    """

    def runTest(self):
        sid_lists = (
            [0b10, 1],
        )
        next_hop_mac = SWITCH2_MAC
        current_level_index = 3
        current_level_value = 0b1

        for sid_list in sid_lists:
            for pkt_type in ["tcpv6", "udpv6", "icmpv6"]:
                print_inline("%s %d SIDs ... " % (pkt_type, len(sid_list)))

                pkt = getattr(testutils, "simple_%s_packet" % pkt_type)()
                pkt =insert_vla_header(pkt, sid_list, current_level_index)


                self.testPacket(pkt, sid_list, current_level_value, current_level_index, next_hop_mac)

    @autocleanup
    def testPacket(self, pkt, sid_list, current_level_value, current_level_index, next_hop_mac):

        incorrect_next_hop_mac = SWITCH3_MAC;

        # *** TODO EXERCISE 6
        # Modify names to match content of P4Info file (look for the fully
        # qualified name of tables, match fields, and actions.
        # ---- START SOLUTION ----

        # Add entry to "My Station" table. Consider the given pkt's eth dst addr
        # as myStationMac address.

        self.insert(self.helper.build_table_entry(
        table_name="IngressPipeImpl.my_station_table",
        match_fields={
                # Exact match.
                "hdr.ethernet.dst_addr": pkt[Ether].dst
            },
            action_name="NoAction"
        ))

        self.insert(self.helper.build_table_entry(
            table_name="IngressPipeImpl.vla_level_table",
            match_fields={
                # Exact match.
                "hdr.vlah.current_level": current_level_index
            },
            action_name="NoAction"
        ))

        self.insert(self.helper.build_table_entry(
            table_name="IngressPipeImpl.vla_level_value_table",
            match_fields={
                # Exact match.
                "local_metadata.vla_current_level_value": current_level_value
            },
            action_name="NoAction"
        ))

        self.insert(self.helper.build_table_entry(
            table_name="IngressPipeImpl.vla_route_to_parent_table",
            match_fields={
                # Exact match.
                "hdr.vlah.current_level": current_level_index
            },
            action_name="IngressPipeImpl.vla_route_to_parent",
            action_params={
                "target_mac": next_hop_mac
            }
        ))

        # Insert SRv6 header when matching the pkt's IPV6 dst addr.
        # Action name an params are generated based on the number of SIDs given.
        # For example, with 2 SIDs:
        # action_name = IngressPipeImpl.srv6_t_insert_2
        # action_params = {
        #     "s1": sid[0],
        #     "s2": sid[1]
        # }


        # Insert ECMP group with only one member (next_hop_mac)
        self.insert(self.helper.build_act_prof_group(
            act_prof_name="IngressPipeImpl.ecmp_selector",
            group_id=1,
            actions=[
                # List of tuples (action name, {action param: value})
                ("IngressPipeImpl.set_next_hop", {"next_hop_mac": incorrect_next_hop_mac}),
            ]
        ))

        # Now that we inserted the SRv6 header, we expect the pkt's IPv6 dst
        # addr to be the first on the SID list.
        # Match on L3 routing table.
        first_sid = sid_list[0]
        self.insert(self.helper.build_table_entry(
            table_name="IngressPipeImpl.routing_v6_table",
            match_fields={
                # LPM match (value, prefix)
                "hdr.ipv6.dst_addr": (first_sid, 128)
            },
            group_id=1
        ))

        # Map next_hop_mac to output port
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

        # Build expected packet from the given one...
        exp_pkt = pkt.copy()

        # Route and decrement TTL
        pkt_route(exp_pkt, next_hop_mac)

        exp_pkt[IPv6ExtHdrVLA].current_level = 2;
        #pkt_decrement_ttl(exp_pkt)

        # Bonus: update P4 program to calculate correct checksum
        set_cksum(pkt, 1)
        set_cksum(exp_pkt, 1)

        # print("packet  vla hex dump ", pkt[IPv6ExtHdrVLA])

        # print("packet  ip hex dump ", pkt[IPv6])

        print ("packet contents")
        pkt.show()

        print("expected packet is ")
        exp_pkt.show()

        # print("exp packet  vla hex dump ", pkt[IPv6ExtHdrVLA])



        testutils.send_packet(self, self.port1, str(pkt))
        testutils.verify_packet(self, exp_pkt, self.port2)

@group("vla")
class VlaRouteDownwards(P4RuntimeTest):
    """Tests Vla Routing Behaviour when current device is in the path to the packet destination in a lower level
    """

   

    def runTest(self):
        sid_lists = (
            [1, 2, 3, 1],
        )
        next_hop_mac = SWITCH2_MAC
        current_level_index = 2
        current_level_value = 2
        next_level_value = 3
        destinationIp = HOST2_IPV6

        for sid_list in sid_lists:
            for pkt_type in ["tcpv6", "udpv6", "icmpv6"]:
                print_inline("%s %d SIDs ... " % (pkt_type, len(sid_list)))

                pkt = getattr(testutils, "simple_%s_packet" % pkt_type)()
                pkt =insert_vla_header(pkt, sid_list, current_level_index)


                self.testPacket(pkt, sid_list, current_level_value, current_level_index, next_level_value,  next_hop_mac, destinationIp)

    @autocleanup
    def testPacket(self, pkt, sid_list, current_level_value, current_level_index, next_level_value, next_hop_mac, destinationIp):

        # *** TODO EXERCISE 6
        # Modify names to match content of P4Info file (look for the fully
        # qualified name of tables, match fields, and actions.
        # ---- START SOLUTION ----

        # Add entry to "My Station" table. Consider the given pkt's eth dst addr
        # as myStationMac address.


        incorrect_next_hop_mac = SWITCH3_MAC;

        self.insert(self.helper.build_table_entry(
        table_name="IngressPipeImpl.my_station_table",
        match_fields={
                # Exact match.
                "hdr.ethernet.dst_addr": pkt[Ether].dst
            },
            action_name="NoAction"
        ))

        self.insert(self.helper.build_table_entry(
            table_name="IngressPipeImpl.vla_level_table",
            match_fields={
                # Exact match.
                "hdr.vlah.current_level": current_level_index
            },
            action_name="NoAction"
        ))

        self.insert(self.helper.build_table_entry(
            table_name="IngressPipeImpl.vla_level_value_table",
            match_fields={
                # Exact match.
                "local_metadata.vla_current_level_value": current_level_value
            },
            action_name="NoAction"
        ))

        self.insert(self.helper.build_table_entry(
            table_name="IngressPipeImpl.vla_route_children_table",
            match_fields={
                # Exact match.
                "local_metadata.vla_next_level_value": next_level_value
            },
            action_name="IngressPipeImpl.vla_route_to_child",
            action_params={
                "target_mac": next_hop_mac
            }
        ))


        self.insert(self.helper.build_table_entry(
            table_name="IngressPipeImpl.vla_route_to_parent_table",
            match_fields={
                # Exact match.
                "hdr.vlah.current_level": current_level_index
            },
            action_name="IngressPipeImpl.vla_route_to_parent",
            action_params={
                "target_mac": incorrect_next_hop_mac
            }
        ))




        # Insert ECMP group with only one member (next_hop_mac)
        self.insert(self.helper.build_act_prof_group(
            act_prof_name="IngressPipeImpl.ecmp_selector",
            group_id=1,
            actions=[
                # List of tuples (action name, {action param: value})
                ("IngressPipeImpl.set_next_hop", {"next_hop_mac": incorrect_next_hop_mac}),
            ]
        ))

        # Add some IP to destination IP table

        
        self.insert(self.helper.build_table_entry(
            table_name="IngressPipeImpl.routing_v6_table",
            match_fields={
                # LPM match (value, prefix)
                "hdr.ipv6.dst_addr": (destinationIp, 128)
            },
            group_id=1
        ))

        # Map next_hop_mac to output port
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

        # Build expected packet from the given one...
        exp_pkt = pkt.copy()

        # Route and decrement TTL
        pkt_route(exp_pkt, next_hop_mac)

        exp_pkt[IPv6ExtHdrVLA].current_level = 3;
        #pkt_decrement_ttl(exp_pkt)

        # Bonus: update P4 program to calculate correct checksum
        set_cksum(pkt, 1)
        set_cksum(exp_pkt, 1)

        # print("packet  vla hex dump ", pkt[IPv6ExtHdrVLA])

        # print("packet  ip hex dump ", pkt[IPv6])

   

        # print("exp packet  vla hex dump ", pkt[IPv6ExtHdrVLA])



        testutils.send_packet(self, self.port1, str(pkt))
        testutils.verify_packet(self, exp_pkt, self.port2)


# Collection of test cases to mimic a normal vla routing from 10.3.6.2 to 10.2.4.1
@group("vla")
class VlaRouteToAnotherTreeFirstSwitch(P4RuntimeTest):
    """
    Currently at 10.3.6
    """

    level_value_list = [10, 3, 6]

    def runTest(self):
        sid_lists = (
            [10,2,4,1],
        )
        next_hop_mac = SWITCH2_MAC
        current_level_index = 3
        current_level_value = 2
        next_level_value = 1
        destinationIp = HOST2_IPV6

        for sid_list in sid_lists:
            for pkt_type in ["tcpv6", "udpv6", "icmpv6"]:
                print_inline("%s %d SIDs ... " % (pkt_type, len(sid_list)))

                pkt = getattr(testutils, "simple_%s_packet" % pkt_type)()
                pkt =insert_vla_header(pkt, sid_list, current_level_index)


                self.testPacket(pkt, sid_list, current_level_value, current_level_index, next_level_value,  next_hop_mac, destinationIp)

    @autocleanup
    def testPacket(self, pkt, sid_list, current_level_value, current_level_index, next_level_value, next_hop_mac, destinationIp):

        # *** TODO EXERCISE 6
        # Modify names to match content of P4Info file (look for the fully
        # qualified name of tables, match fields, and actions.
        # ---- START SOLUTION ----

        # Add entry to "My Station" table. Consider the given pkt's eth dst addr
        # as myStationMac address.


        incorrect_next_hop_mac = SWITCH3_MAC;

        self.insert(self.helper.build_table_entry(
        table_name="IngressPipeImpl.my_station_table",
        match_fields={
                # Exact match.
                "hdr.ethernet.dst_addr": pkt[Ether].dst
            },
            action_name="NoAction"
        ))

        self.insert(self.helper.build_table_entry(
            table_name="IngressPipeImpl.vla_level_table",
            match_fields={
                # Exact match.
                "hdr.vlah.current_level": current_level_index
            },
            action_name="NoAction"
        ))

        self.insert(self.helper.build_table_entry(
            table_name="IngressPipeImpl.vla_level_value_table",
            match_fields={
                # Exact match.
                "local_metadata.vla_current_level_value": current_level_value
            },
            action_name="NoAction"
        ))

        self.insert(self.helper.build_table_entry(
            table_name="IngressPipeImpl.vla_route_children_table",
            match_fields={
                # Exact match.
                "local_metadata.vla_next_level_value": next_level_value
            },
            action_name="IngressPipeImpl.vla_route_to_child",
            action_params={
                "target_mac": incorrect_next_hop_mac
            }
        ))


        self.insert(self.helper.build_table_entry(
            table_name="IngressPipeImpl.vla_route_to_parent_table",
            match_fields={
                # Exact match.
                "hdr.vlah.current_level": current_level_index
            },
            action_name="IngressPipeImpl.vla_route_to_parent",
            action_params={
                "target_mac": next_hop_mac
            }
        ))




        # Insert ECMP group with only one member (next_hop_mac)
        self.insert(self.helper.build_act_prof_group(
            act_prof_name="IngressPipeImpl.ecmp_selector",
            group_id=1,
            actions=[
                # List of tuples (action name, {action param: value})
                ("IngressPipeImpl.set_next_hop", {"next_hop_mac": incorrect_next_hop_mac}),
            ]
        ))

        # Add some IP to destination IP table

        
        self.insert(self.helper.build_table_entry(
            table_name="IngressPipeImpl.routing_v6_table",
            match_fields={
                # LPM match (value, prefix)
                "hdr.ipv6.dst_addr": (destinationIp, 128)
            },
            group_id=1
        ))

        # Map next_hop_mac to output port
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

        # Build expected packet from the given one...
        exp_pkt = pkt.copy()

        # Route and decrement TTL
        pkt_route(exp_pkt, next_hop_mac)

        exp_pkt[IPv6ExtHdrVLA].current_level = 2;
        #pkt_decrement_ttl(exp_pkt)

        # Bonus: update P4 program to calculate correct checksum
        set_cksum(pkt, 1)
        set_cksum(exp_pkt, 1)

        # print("packet  vla hex dump ", pkt[IPv6ExtHdrVLA])

        # print("packet  ip hex dump ", pkt[IPv6])

   

        # print("exp packet  vla hex dump ", pkt[IPv6ExtHdrVLA])



        testutils.send_packet(self, self.port1, str(pkt))
        testutils.verify_packet(self, exp_pkt, self.port2)