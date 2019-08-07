from pox.core import core
from pox.openflow import *
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.addresses import EthAddr, IPAddr
log = core.getLogger()
import time
import random
import json # addition to read configuration from file
from threading import Thread


class SimpleLoadBalancer(object):

    
    # initialize SimpleLoadBalancer class instance
    def __init__(self, lb_mac = None, service_ip = None, 
                 server_ips = [], user_ip_to_group = {}, server_ip_to_group = {}):
        
        # add the necessary openflow listeners
        core.openflow.addListeners(self)
        # set class parameters
        # write your code here!!!
        print "__init__"
        self.lb_mac=lb_mac
        self.service_ip=service_ip
        self.server_ips=server_ips
        self.user_ip_to_group=user_ip_to_group
        self.server_ip_to_group=server_ip_to_group
        self.ip_to_mac_port={}
        self.group_to_server_ip={}
        self.lb_mapping={}
        for x,y in self.server_ip_to_group.items():
            if y in self.group_to_server_ip:
                self.group_to_server_ip[y].append(x)
            else:
                self.group_to_server_ip[y]=[x]
        pass


    # respond to switch connection up event
    def _handle_ConnectionUp(self, event):
        for x in self.server_ips:
            #t=Thread(target=self.send_proxied_arp_request, args=(event.connection, x,))
            self.send_proxied_arp_request(event.connection, x)
            #t.start()
        #for t in threads:
            #t.join()
        #while len(server_ip_to_mac_port)!=len(self.server_ips):
            #time.sleep(0.5)
        pass


    # update the load balancing choice for a certain client
    def update_lb_mapping(self, client_ip):
        # write your code here!!!
        print "update_lb_mapping"
        self.lb_mapping[client_ip]=random.choice(self.group_to_server_ip[self.user_ip_to_group[client_ip]])
        pass
    

    # send ARP reply "proxied" by the controller (on behalf of another machine in network)
    def send_proxied_arp_reply(self, packet, connection, outport, requested_mac):
        # write your code here!!!
        print "send_proxied_arp_reply"
        if packet.next.protodst==IPAddr(self.service_ip):
            self.ip_to_mac_port[packet.next.protosrc]={'mac':packet.src, 'port':outport}
            r=arp(opcode=2,hwsrc=EthAddr(self.lb_mac),hwdst=EthAddr(requested_mac),protosrc=IPAddr(self.service_ip),protodst=IPAddr(packet.next.protosrc))  
        else:
            r=arp(opcode=2,hwsrc=EthAddr(self.lb_mac),hwdst=EthAddr(requested_mac),protosrc=packet.next.protodst,protodst=IPAddr(packet.next.protosrc))
        e=ethernet(type=ethernet.ARP_TYPE, src=EthAddr(self.lb_mac),dst=EthAddr(requested_mac))
        e.set_payload(r)
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port = outport))
        connection.send(msg)
        pass


    # send ARP request "proxied" by the controller (so that the controller learns about another machine in network)
    def send_proxied_arp_request(self, connection, ip):
        # write your code here!!!
        r=arp(opcode=1, hwsrc=EthAddr(self.lb_mac),hwdst=EthAddr("FF:FF:FF:FF:FF:FF"),protosrc=IPAddr(self.service_ip),protodst=IPAddr(ip))   
        e=ethernet(type=ethernet.ARP_TYPE, src=EthAddr(self.lb_mac),dst=EthAddr("FF:FF:FF:FF:FF:FF"))
        e.set_payload(r)
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        connection.send(msg)
        pass

    
    # install flow rule from a certain client to a certain server
    def install_flow_rule_client_to_server(self, packet, connection, outport, client_ip, server_ip, buffer_id=of.NO_BUFFER):
        # write your code here!!!
        print "install_flow_rule_client_to_server"
        actions=[]
        actions.append(of.ofp_action_dl_addr.set_dst(str(self.ip_to_mac_port[server_ip]['mac'])))
        actions.append(of.ofp_action_dl_addr.set_src(str(self.lb_mac)))
        actions.append(of.ofp_action_nw_addr.set_dst(str(server_ip)))
        actions.append(of.ofp_action_output(port = outport))
        msg=of.ofp_flow_mod()
        msg.idle_timeout=10
        msg.buffer_id=buffer_id
        msg.actions=actions
        msg.match=of.ofp_match(in_port=self.ip_to_mac_port[client_ip]['port'], dl_type=0x800)
        connection.send(msg)    
        pass


    # install flow rule from a certain server to a certain client
    def install_flow_rule_server_to_client(self, packet, connection, outport, server_ip, client_ip, buffer_id=of.NO_BUFFER):
        # write your code here!!!
        print "install_ flow rule server to client"
        actions=[]
        actions.append(of.ofp_action_dl_addr.set_dst(str(self.ip_to_mac_port[client_ip]['mac'])))
        actions.append(of.ofp_action_dl_addr.set_src(str(self.lb_mac)))
        actions.append(of.ofp_action_nw_addr.set_src(str(self.service_ip)))
        actions.append(of.ofp_action_output(port = outport))
        msg=of.ofp_flow_mod()
        msg.idle_timeout=10
        msg.buffer_id=buffer_id
        msg.actions=actions
        #UPARXEI THEMA EDW BAINOUN KAI APO TIN IDIA PORTA
        msg.match=of.ofp_match(in_port=self.ip_to_mac_port[server_ip]['port'], dl_type=0x800)
        connection.send(msg)
        pass


    # main packet-in handling routine
    def _handle_PacketIn(self, event):
        packet = event.parsed
        connection = event.connection
        inport = event.port
        if packet.type == packet.ARP_TYPE:
            # write your code here!!!
            if packet.next.opcode==1:
                self.send_proxied_arp_reply(packet, connection, inport, packet.next.hwsrc)
            elif packet.next.opcode==2:
                self.ip_to_mac_port[packet.next.protosrc]={'mac':packet.src, 'port':inport}
            else:
                log.info("Unknown ARP opcode: %s" % packet.next.opcode)
                return
            pass
        elif packet.type == packet.IP_TYPE:
            if packet.next.dstip==IPAddr("10.1.2.3"):
                while packet.next.srcip not in self.ip_to_mac_port:
                    time.sleep(0.001)
                self.update_lb_mapping(packet.next.srcip)
                self.install_flow_rule_client_to_server(packet, connection, self.ip_to_mac_port[self.lb_mapping[packet.next.srcip]]['port'], packet.next.srcip, self.lb_mapping[packet.next.srcip], event.ofp.buffer_id)
            else:
                self.install_flow_rule_server_to_client(packet, connection, self.ip_to_mac_port[packet.next.dstip]['port'], packet.next.srcip, packet.next.dstip, event.ofp.buffer_id)
            pass
        else:
            log.info("Unknown Packet type: %s" % packet.type)
            return
        return


# extra function to read json files
def load_json_dict(json_file):
    json_dict = {}    
    with open(json_file, 'r') as f:
        json_dict = json.load(f)
    return json_dict


# main launch routine
def launch(configuration_json_file):
    log.info("Loading Simple Load Balancer module")
    
    # load the configuration from file    
    configuration_dict = load_json_dict(configuration_json_file)   

    # the service IP that is publicly visible from the users' side   
    service_ip = IPAddr(configuration_dict['service_ip'])

    # the load balancer MAC with which the switch responds to ARP requests from users/servers
    lb_mac = EthAddr(configuration_dict['lb_mac'])

    # the IPs of the servers
    server_ips = [IPAddr(x) for x in configuration_dict['server_ips']]    

    # map users (IPs) to service groups (e.g., 10.0.0.5 to 'red')    
    user_ip_to_group = {}
    for user_ip,group in configuration_dict['user_groups'].items():
        user_ip_to_group[IPAddr(user_ip)] = group

    # map servers (IPs) to service groups (e.g., 10.0.0.1 to 'blue')
    server_ip_to_group = {}
    for server_ip,group in configuration_dict['server_groups'].items():
        server_ip_to_group[IPAddr(server_ip)] = group

    # do the launch with the given parameters
    core.registerNew(SimpleLoadBalancer, lb_mac, service_ip, server_ips, user_ip_to_group, server_ip_to_group)
    log.info("Simple Load Balancer module loaded")
