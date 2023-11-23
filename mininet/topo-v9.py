#!/usr/bin/python

#  Copyright 2019-present Open Networking Foundation
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import argparse
import os

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import Host
from mininet.topo import Topo
from mininet.link import TCLink
from stratum import StratumBmv2Switch
import mininetUtil

CPU_PORT = 255


class IPv6Host(Host):
    """Host that can be configured with an IPv6 gateway (default route).
    """

    def config(self, ipv6, ipv6_gw=None, **params):
        super(IPv6Host, self).config(**params)
        self.cmd('ip -4 addr flush dev %s' % self.defaultIntf())
        self.cmd('ip -6 addr flush dev %s' % self.defaultIntf())
        self.cmd('ip -6 addr add %s dev %s' % (ipv6, self.defaultIntf()))
        if ipv6_gw:
            self.cmd('ip -6 route add default via %s' % ipv6_gw)
        # Disable offload
        for attr in ["rx", "tx", "sg"]:
            cmd = "/sbin/ethtool --offload %s %s off" % (self.defaultIntf(), attr)
            self.cmd(cmd)

        def updateIP():
            return ipv6.split('/')[0]

        self.defaultIntf().updateIP = updateIP

    def terminate(self):
        super(IPv6Host, self).terminate()


class TutorialTopo(Topo):
    """2x2 fabric topology with IPv6 hosts"""

    def __init__(self, *args, **kwargs):
        Topo.__init__(self, *args, **kwargs)

        # Leaves
        # gRPC port 50001
        leaf1 = self.addSwitch('leaf1', cls=StratumBmv2Switch, cpuport=CPU_PORT)
        # gRPC port 50002
        leaf2 = self.addSwitch('leaf2', cls=StratumBmv2Switch, cpuport=CPU_PORT)

        # 50003
        leaf3 = self.addSwitch('leaf3', cls=StratumBmv2Switch, cpuport= CPU_PORT)

        #50004
        leaf4 = self.addSwitch('leaf4', cls =StratumBmv2Switch, cpuport = CPU_PORT)

         #50005
        leaf5 = self.addSwitch('leaf5', cls =StratumBmv2Switch, cpuport = CPU_PORT)

         #50006
        leaf6 = self.addSwitch('leaf6', cls =StratumBmv2Switch, cpuport = CPU_PORT)

        # Spines
        # gRPC port 50007
        spine1 = self.addSwitch('spine1', cls=StratumBmv2Switch, cpuport=CPU_PORT)
       
    

        # Switch Links
        self.addLink(spine1, leaf1, bw=mininetUtil.LINK_BANDWIDTH, delay = mininetUtil.LINK_DELAY, max_queue_size=mininetUtil.LINK_MAX_QUEUE_SIZE)
        self.addLink(spine1, leaf4, bw=mininetUtil.LINK_BANDWIDTH, delay = mininetUtil.LINK_DELAY, max_queue_size=mininetUtil.LINK_MAX_QUEUE_SIZE)

        self.addLink(leaf1, leaf2, bw=mininetUtil.LINK_BANDWIDTH, delay = mininetUtil.LINK_DELAY, max_queue_size=mininetUtil.LINK_MAX_QUEUE_SIZE)
        self.addLink(leaf1, leaf3, bw=mininetUtil.LINK_BANDWIDTH, delay = mininetUtil.LINK_DELAY, max_queue_size=mininetUtil.LINK_MAX_QUEUE_SIZE)

        self.addLink(leaf4, leaf5, bw=mininetUtil.LINK_BANDWIDTH, delay = mininetUtil.LINK_DELAY, max_queue_size=mininetUtil.LINK_MAX_QUEUE_SIZE)
        self.addLink(leaf5, leaf6, bw=mininetUtil.LINK_BANDWIDTH, delay = mininetUtil.LINK_DELAY, max_queue_size=mininetUtil.LINK_MAX_QUEUE_SIZE)


    

        # IPv6 hosts attached to leaf 1
        h1a = self.addHost('h1a', cls=IPv6Host, mac="00:00:00:00:00:1A",
                           ipv6='2001:1:1:4::a/66', ipv6_gw='2001:1:1:4::ff')
        self.addLink(h1a, leaf1, bw=mininetUtil.LINK_BANDWIDTH, delay = mininetUtil.LINK_DELAY, max_queue_size=mininetUtil.LINK_MAX_QUEUE_SIZE)  
        

        h2a = self.addHost('h2a', cls=IPv6Host, mac="00:00:00:00:00:1B",
                           ipv6='2001:1:1:8:4::a/68', ipv6_gw='2001:1:1:8:4::ff')
        
        self.addLink(h2a, leaf2, bw=mininetUtil.LINK_BANDWIDTH, delay = mininetUtil.LINK_DELAY, max_queue_size=mininetUtil.LINK_MAX_QUEUE_SIZE)  

       
        h3a = self.addHost('h3a', cls=IPv6Host, mac="00:00:00:00:00:1C",
                          ipv6='2001:1:1:C:4::a/68', ipv6_gw='2001:1:1:C:4::ff')
        
        self.addLink(h3a, leaf3, bw=mininetUtil.LINK_BANDWIDTH, delay = mininetUtil.LINK_DELAY, max_queue_size=mininetUtil.LINK_MAX_QUEUE_SIZE)
        
        h4a = self.addHost('h4a', cls=IPv6Host, mac="00:00:00:00:00:2A",
                          ipv6='2001:1:4:8::a/66', ipv6_gw='2001:1:4:8::ff')
        
        self.addLink(h4a, leaf4, bw=mininetUtil.LINK_BANDWIDTH, delay = mininetUtil.LINK_DELAY, max_queue_size=mininetUtil.LINK_MAX_QUEUE_SIZE)


        h5a = self.addHost('h5a', cls=IPv6Host, mac="00:00:00:00:00:2B",
                          ipv6='2001:1:4:4:8::a/68', ipv6_gw='2001:1:4:4:8::ff')
        
        self.addLink(h5a, leaf5, bw=mininetUtil.LINK_BANDWIDTH, delay = mininetUtil.LINK_DELAY, max_queue_size=mininetUtil.LINK_MAX_QUEUE_SIZE)

        h6a = self.addHost('h6a', cls=IPv6Host, mac="00:00:00:00:00:2C",
                          ipv6='2001:1:4:4:4:4::a/70', ipv6_gw='2001:1:4:4:4:4::ff')
        
        self.addLink(h6a, leaf6, bw=mininetUtil.LINK_BANDWIDTH, delay = mininetUtil.LINK_DELAY, max_queue_size=mininetUtil.LINK_MAX_QUEUE_SIZE)

        h6b = self.addHost('h6b', cls=IPv6Host, mac="00:00:00:00:00:2D",
                          ipv6='2001:1:4:4:4:4::b/70', ipv6_gw='2001:1:4:4:4:4::ff')
        
        self.addLink(h6b, leaf6, bw=mininetUtil.LINK_BANDWIDTH, delay = mininetUtil.LINK_DELAY, max_queue_size=mininetUtil.LINK_MAX_QUEUE_SIZE)
        

def main():
    net = Mininet(Link=TCLink, topo=TutorialTopo(), controller=None)
    net.start()
    hostInfo = mininetUtil.get_hosts_info(net)
    csvFilePath = "/home/hostMacs.csv"
    mininetUtil.write_to_csv(csvFilePath, hostInfo)
    current_directory = os.getcwd()
    print("Current Directory:", current_directory)
    CLI(net)
    net.stop()
    print '#' * 80
    print 'ATTENTION: Mininet was stopped! Perhaps accidentally?'
    print 'No worries, it will restart automatically in a few seconds...'
    print 'To access again the Mininet CLI, use `make mn-cli`'
    print 'To detach from the CLI (without stopping), press Ctrl-D'
    print 'To permanently quit Mininet, use `make stop`'
    print '#' * 80

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Mininet topology script for 2x2 fabric with stratum_bmv2 and IPv6 hosts')
    args = parser.parse_args()
    setLogLevel('info')

    main()
