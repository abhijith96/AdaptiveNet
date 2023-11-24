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

        leaf3 = self.addSwitch('leaf3', cls=StratumBmv2Switch, cpuport=CPU_PORT)
        

        leaf4 = self.addSwitch('leaf4', cls=StratumBmv2Switch, cpuport=CPU_PORT)
        leaf5 = self.addSwitch('leaf5', cls=StratumBmv2Switch, cpuport=CPU_PORT)
        leaf6 = self.addSwitch('leaf6', cls=StratumBmv2Switch, cpuport=CPU_PORT)
        leaf7 = self.addSwitch('leaf7', cls=StratumBmv2Switch, cpuport=CPU_PORT)
        leaf8 = self.addSwitch('leaf8', cls=StratumBmv2Switch, cpuport=CPU_PORT)
        leaf9 = self.addSwitch('leaf9', cls=StratumBmv2Switch, cpuport=CPU_PORT)
        leaf10 = self.addSwitch('leaf10', cls=StratumBmv2Switch, cpuport=CPU_PORT)
        leaf11 = self.addSwitch('leaf11', cls=StratumBmv2Switch, cpuport=CPU_PORT)
        leaf12 = self.addSwitch('leaf12', cls=StratumBmv2Switch, cpuport=CPU_PORT)
        leaf13 = self.addSwitch('leaf13', cls=StratumBmv2Switch, cpuport=CPU_PORT)
        leaf14 = self.addSwitch('leaf14', cls=StratumBmv2Switch, cpuport=CPU_PORT)
        leaf15 = self.addSwitch('leaf15', cls=StratumBmv2Switch, cpuport=CPU_PORT)
        leaf16 = self.addSwitch('leaf16', cls=StratumBmv2Switch, cpuport=CPU_PORT)
        leaf17 = self.addSwitch('leaf17', cls=StratumBmv2Switch, cpuport=CPU_PORT)
        leaf18 = self.addSwitch('leaf18', cls=StratumBmv2Switch, cpuport=CPU_PORT)
        leaf19 = self.addSwitch('leaf19', cls=StratumBmv2Switch, cpuport=CPU_PORT)
        leaf20 = self.addSwitch('leaf20', cls=StratumBmv2Switch, cpuport=CPU_PORT)
        

      

        # Switch Links
        self.addLink(leaf1, leaf2)
        self.addLink(leaf1, leaf3)
        self.addLink(leaf1, leaf4)
       
        self.addLink(leaf2, leaf5)

        self.addLink(leaf2, leaf6)

        h1a = self.addHost('h1a', cls=IPv6Host, mac="00:00:00:00:00:1A",
                           ipv6='2001:1::a/48', ipv6_gw='2001:1::ff')
        h2a = self.addHost('h2a', cls=IPv6Host, mac="00:00:00:00:00:1B",
                           ipv6='2001:1:0:2000::a/51', ipv6_gw='2001:1:0:2000::ff')
        h5a = self.addHost('h5a', cls=IPv6Host, mac="00:00:00:00:00:1C",
                           ipv6='2001:1:0:1000::a/52', ipv6_gw='2001:1:0:1000::ff')
        h6a = self.addHost('h6a', cls=IPv6Host, mac="00:00:00:00:00:1D",
                           ipv6='2001:1::a/53', ipv6_gw='2001:1::ff')

        self.addLink(h1a, leaf1)  # port 3
        self.addLink(h2a, leaf2)  # port 4
        self.addLink(h5a, leaf5)  # port 5
        self.addLink(h6a, leaf6)


        h3a = self.addHost('h3a', cls=IPv6Host, mac="00:00:00:00:00:2A",
                           ipv6='2001:1:0:4000::a/50', ipv6_gw='2001:1:0:4000::ff')
        h7a = self.addHost('h7a', cls=IPv6Host, mac="00:00:00:00:00:2B",
                           ipv6='2001:1:0:4000::a/51', ipv6_gw='2001:1:1::ff')
        h15a = self.addHost('h15a', cls=IPv6Host, mac="00:00:00:00:00:2C",
                        ipv6='2001:1:0:4000::a/52', ipv6_gw='2001:1:1::ff')
        h16a = self.addHost('h16a', cls=IPv6Host, mac="00:00:00:00:00:2D",
                        ipv6='2001:1:1::a/64', ipv6_gw='2001:1:1::ff')
        h17a = self.addHost('h17a', cls=IPv6Host, mac="00:00:00:00:00:2E",
                        ipv6='2001:1:1::a/64', ipv6_gw='2001:1:1::ff')
        h18a = self.addHost('h18a', cls=IPv6Host, mac="00:00:00:00:00:2F",
                        ipv6='2001:1:1::a/64', ipv6_gw='2001:1:1::ff')
        h19a = self.addHost('h19a', cls=IPv6Host, mac="00:00:00:00:01:2A",
                        ipv6='2001:1:1::a/64', ipv6_gw='2001:1:1::ff')
        h20a = self.addHost('h20a', cls=IPv6Host, mac="00:00:00:00:01:2B",
                        ipv6='2001:1:1::a/64', ipv6_gw='2001:1:1::ff')
        

        self.addLink(h3a, leaf3)  # port 3
        self.addLink(h7a, leaf7)  # port 4
        self.addLink(h15a, leaf15) 
        self.addLink(h16a, leaf16)
        self.addLink(h17a, leaf17)
        self.addLink(h18a, leaf18)
        self.addLink(h19a, leaf19)
        self.addLink(h20a, leaf20)




        h4a = self.addHost('h3a', cls=IPv6Host, mac="00:00:00:00:00:3A",
                           ipv6='2001:1:1::a/64', ipv6_gw='2001:1:1::ff')
        h8a = self.addHost('h8a', cls=IPv6Host, mac="00:00:00:00:00:3B",
                           ipv6='2001:1:1::a/64', ipv6_gw='2001:1:1::ff')
        h9a = self.addHost('h9a', cls=IPv6Host, mac="00:00:00:00:00:3C",
                        ipv6='2001:1:1::a/64', ipv6_gw='2001:1:1::ff')
        h10a = self.addHost('h10a', cls=IPv6Host, mac="00:00:00:00:00:3D",
                        ipv6='2001:1:1::a/64', ipv6_gw='2001:1:1::ff')
        h11a = self.addHost('h11a', cls=IPv6Host, mac="00:00:00:00:00:3E",
                        ipv6='2001:1:1::a/64', ipv6_gw='2001:1:1::ff')
        h12a = self.addHost('h12a', cls=IPv6Host, mac="00:00:00:00:00:3F",
                        ipv6='2001:1:1::a/64', ipv6_gw='2001:1:1::ff')
        h13a = self.addHost('h13a', cls=IPv6Host, mac="00:00:00:00:01:3A",
                        ipv6='2001:1:1::a/64', ipv6_gw='2001:1:1::ff')
        h14a = self.addHost('h14a', cls=IPv6Host, mac="00:00:00:00:01:3B",
                        ipv6='2001:1:1::a/64', ipv6_gw='2001:1:1::ff')
        

        self.addLink(h4a, leaf4)  
        self.addLink(h9a, leaf9) 
        self.addLink(h10a, leaf10)
        self.addLink(h11a, leaf11)
        self.addLink(h12a, leaf12)
        self.addLink(h13a, leaf13)
        self.addLink(h14a, leaf14)
     

def main():
    net = Mininet(topo=TutorialTopo(), controller=None)
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
