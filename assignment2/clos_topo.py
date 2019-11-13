#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import irange,dumpNodeConnections
from mininet.log import setLogLevel
from mininet.node import RemoteController

import argparse
import sys
import time


class ClosTopo(Topo):

    def __init__(self, fanout, cores, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)
       
        "Set up Core and Aggregate level, Connection Core - Aggregation level"
        #WRITE YOUR CODE HERE!
        corelist=[]
        aggregatelist=[]
        edgelist=[]
        counter=1
        for switch in range(cores):
            corelist.append(self.addSwitch('c%s'%(counter)))
            counter=counter+1

        for core in corelist:
            for switch in range(fanout):
                aggregatelist.append(self.addSwitch('a%s'%(counter)))
                counter=counter+1
            
        for core in corelist:
            for aggregate in aggregatelist:
                self.addLink(core, aggregate)

        pass

        "Set up Edge level, Connection Aggregation - Edge level "
        #WRITE YOUR CODE HERE!
        for aggregate in aggregatelist:
            for switch in range(fanout):
                edgelist.append(self.addSwitch('e%s'%(counter)))
                counter=counter+1
        
        for aggregate in aggregatelist:
            for edge in edgelist:
                self.addLink(aggregate, edge)
        pass
        
        counter=1
        "Set up Host level, Connection Edge - Host level "
        #WRITE YOUR CODE HERE!
        for edge in edgelist:
            for host in range(2):
                temp=self.addHost('h%s'%(counter))
                self.addLink(edge, temp)
                counter=counter+1
        pass
	

def setup_clos_topo(fanout=2, cores=1):
    "Create and test a simple clos network"
    assert(fanout>0)
    assert(cores>0)
    topo = ClosTopo(fanout, cores)
    net = Mininet(topo=topo, controller=lambda name: RemoteController('c0', "127.0.0.1"), autoSetMacs=True, link=TCLink)
    net.start()
    time.sleep(20) #wait 20 sec for routing to converge
    net.pingAll()  #test all to all ping and learn the ARP info over this process
    CLI(net)       #invoke the mininet CLI to test your own commands
    net.stop()     #stop the emulation (in practice Ctrl-C from the CLI 
                   #and then sudo mn -c will be performed by programmer)

    
def main(argv):
    parser = argparse.ArgumentParser(description="Parse input information for mininet Clos network")
    parser.add_argument('--num_of_core_switches', '-c', dest='cores', type=int, help='number of core switches')
    parser.add_argument('--fanout', '-f', dest='fanout', type=int, help='network fanout')
    args = parser.parse_args(argv)
    setLogLevel('info')
    setup_clos_topo(args.fanout, args.cores)


if __name__ == '__main__':
    main(sys.argv[1:])
