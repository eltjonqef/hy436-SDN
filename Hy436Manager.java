/*
 * Copyright 2017-present Open Networking Foundation
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
package org.onosproject.hy436.impl;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Sets;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.apache.felix.scr.annotations.Service;
import org.onlab.packet.ARP;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.IpAddress;
import org.onlab.packet.MacAddress;
import org.onlab.packet.VlanId;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.hy436.Hy436Service;
import org.onosproject.intentsync.IntentSynchronizationService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.HostLocation;
import org.onosproject.net.Link;
import org.onosproject.net.Path;
import org.onosproject.net.PortNumber;
import org.onosproject.net.config.ConfigFactory;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.config.basics.SubjectFactories;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.criteria.VlanIdCriterion;
import org.onosproject.net.flow.criteria.EthTypeCriterion;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.FlowRuleStore;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.host.HostService;
import org.onosproject.net.intent.Constraint;
import org.onosproject.net.intent.HostToHostIntent;
import org.onosproject.net.intent.Key;
import org.onosproject.net.intent.LinkCollectionIntent;
import org.onosproject.net.intent.constraint.PartialFailureConstraint;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.topology.Topology;
import org.onosproject.net.topology.TopologyService;
import org.slf4j.Logger;

import java.nio.ByteBuffer;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.List;
import java.util.ArrayList;

import static org.onlab.packet.Ethernet.TYPE_ARP;
import static org.onlab.packet.Ethernet.TYPE_IPV4;
import static org.onosproject.net.flow.criteria.Criterion.Type.ETH_TYPE;
import static org.onosproject.net.flow.criteria.Criterion.Type.VLAN_VID;
import static org.onlab.packet.VlanId.vlanId;
import static org.slf4j.LoggerFactory.getLogger;

@Component(immediate = true)
@Service
public class Hy436Manager implements Hy436Service {

    /* Static Variables */
    private static final ImmutableList<Constraint> CONSTRAINTS = ImmutableList.of(new PartialFailureConstraint());
    private static final String APP_NAME = "org.onosproject.hy436";
    private static final int PRIORITY = 1000;
    private static final VlanId MON_VLAN = vlanId((short) 200);
    private static final Class<Hy436Config> CONFIG_CLASS = Hy436Config.class;

    /* Logger */
    private final Logger log = getLogger(getClass());

    /* Listeners */
    private final InternalNetworkConfigListener configListener = new InternalNetworkConfigListener();

    /* Services */
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    IntentSynchronizationService intentSynchronizationService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    NetworkConfigRegistry networkConfigRegistry;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    NetworkConfigService networkConfigService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    TopologyService topologyService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    FlowRuleStore flowStore;

    /* Config */
    private ConfigFactory<ApplicationId, Hy436Config> hy436ConfigFactory =
            new ConfigFactory<ApplicationId, Hy436Config>(
                    SubjectFactories.APP_SUBJECT_FACTORY, Hy436Config.class, "hy436") {
                @Override
                public Hy436Config createConfig() {
                    return new Hy436Config();
                }
            };

    /* Variables */
    private ApplicationId appId;
    private Set<IpAddress> monitoredHosts = Sets.newConcurrentHashSet();
    private IpAddress monitor;
    private Hy436Config.Type monitorDirection;
    private Hy436PacketProcessor processor = new Hy436PacketProcessor();

    /* Functions */
    private Function<Host, IpAddress> getAddress = host ->
            host.ipAddresses().stream().findFirst().orElseThrow(
                    () -> new RuntimeException("IP for host " + host + " not Found")
            );

    private Function<IpAddress, Host> getHost = ip ->
            hostService.getHostsByIp(ip).stream().findFirst().orElseThrow(
                    () -> new RuntimeException("Host from IP " + ip + " not Found")
            );

    @Activate
    void activate() {
        appId = coreService.registerApplication(APP_NAME);

        networkConfigService.addListener(configListener);
        networkConfigRegistry.registerConfigFactory(hy436ConfigFactory);
        requestIntercepts();
        packetService.addProcessor(processor, PacketProcessor.director(3));

        log.info("HY436 Started");
    }

    @Deactivate
    void deactivate() {
        flowRuleService.removeFlowRulesById(appId);
        intentSynchronizationService.removeIntentsByAppId(appId);
        withdrawIntercepts();

        log.info("HY436 Stopped");
    }

    /**
     * Request packet in via packet service.
     */
    private void requestIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
    }

    /**
     * Cancel request for packet in via packet service.
     */
    private void withdrawIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
    }

    /**
     * Send an ARP request packet to a specific switch port.
     *
     * @param deviceId   device id of switch
     * @param portNumber port number of switch
     * @param targetIp   target address of ARP request
     */
    private void sendProbe(DeviceId deviceId, PortNumber portNumber, IpAddress targetIp) {
        Ethernet probePacket;
        if (targetIp.isIp4()) {
            probePacket = buildArpRequest(targetIp);

            TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(portNumber).build();

            OutboundPacket outboundPacket = new DefaultOutboundPacket(deviceId, treatment,
                    ByteBuffer.wrap(probePacket.serialize()));

            packetService.emit(outboundPacket);
        } else {
            throw new RuntimeException("Only IPv4 is supported!");
        }
    }

    /**
     * Send a full packet intercepted by the controller, to a specific switch and port.
     *
     * @param deviceId      device id of switch
     * @param portNumber    port number of switch
     * @param ethPkt        packet bytes
     * @param targetHostMac mac of target host (optional)
     */
    private void sendPktOut(DeviceId deviceId, PortNumber portNumber, Ethernet ethPkt, MacAddress targetHostMac) {
        TrafficTreatment.Builder treatmentBuilder = DefaultTrafficTreatment.builder();
        if (targetHostMac != null) {
            treatmentBuilder.setEthDst(targetHostMac);
        }
        treatmentBuilder.setOutput(portNumber);

        OutboundPacket outboundPacket =
                new DefaultOutboundPacket(deviceId, treatmentBuilder.build(), ByteBuffer.wrap(ethPkt.serialize()));

        packetService.emit(outboundPacket);
    }

    /**
     * Build an ARP request for target IP.
     *
     * @param targetIp ip address
     * @return ethernet packet
     */
    private Ethernet buildArpRequest(IpAddress targetIp) {
        return ARP.buildArpRequest(
                MacAddress.BROADCAST.toBytes(),
                Ip4Address.ZERO.toOctets(),
                MacAddress.BROADCAST.toBytes(), targetIp.toOctets(),
                MacAddress.BROADCAST.toBytes(), VlanId.NONE.toShort()
        );
    }

    /**
     * Discovers needed monitors by flooding ARP requests to the network.
     */
    private void discoverMonitors() {
        deviceService.getAvailableDevices().forEach(
                device -> sendProbe(device.id(), PortNumber.FLOOD, monitor)
        );
    }

    /**
     * Installs Intents and Flows to achieve traffic monitoring of a host (src or
     * destination) to monitor.
     *
     * @param src    origin host
     * @param dst    destination host
     * @param ethPkt ethernet packet to handle directly (optional)
     */
    private void fwdAndMonitor(Host src, Host dst, Ethernet ethPkt) {
        /* initialize variables for intents and flow objectives */
        Host mon = getHost.apply(monitor);

        HostLocation destLocation = dst.location();
        HostLocation sourceLocation = src.location();
        HostLocation monLocation = mon.location();

        IpAddress sourceAddress = getAddress.apply(src);
        IpAddress destAddress = getAddress.apply(dst);

        MacAddress monMac = mon.mac();

        /* find the first switch-switch link on each path, if it exists
           (endpoints may also be on the same switch) */
        Topology topology = topologyService.currentTopology();

        Optional<Path> monPath;
        Optional<Path> normPath;
        Optional<Link> monLink;
        Optional<Link> normLink;

        normPath = topologyService.getPaths(topology,
                sourceLocation.deviceId(), destLocation.deviceId()).stream().findFirst();
        monPath = topologyService.getPaths(topology,
                sourceLocation.deviceId(), monLocation.deviceId()).stream().findFirst();
        monLink = monPath.flatMap(path -> path.links().stream().findFirst());
        normLink = normPath.flatMap(path -> path.links().stream().findFirst());

        /* determine if the directional communication should be monitored */
        boolean needsMonitor = false;
        switch (monitorDirection) {
            case INCOMING:
                /* WRITE YOUR CODE HERE */;
                needsMonitor=true;
                break;
            case OUTGOING:
                /* WRITE YOUR CODE HERE */;
                needsMonitor=true;
                break;
            case BOTH:
                needsMonitor=true;
            default:
                /* WRITE YOUR CODE HERE */;
        }

        /* send the current packet directly to the normal destination (first packet of flow) */
        /* WRITE YOUR CODE HERE */;
        sendPktOut(destLocation.deviceId(), destLocation.port(), ethPkt, null);
        /* if source and destination are on different switches, install new link collection intent
           to forward normal traffic along src->dst path */
        if (normLink.isPresent() && normPath.isPresent()) {
            /* WRITE YOUR CODE HERE */;
            installLinkCollectionIntent(src, dst, normPath);
        }
        /* otherwise install a direct flow objective to send normal traffic directly to dst */
        else {
            /* WRITE YOUR CODE HERE */;
            installForwardObjective(src, dst);
        }

        /* remote TAP: monitor traffic from a remote location (at least one hop away from
           the endpoints) */
        if (needsMonitor && monLink.isPresent() && monPath.isPresent()) {

            /* send the packet clone directly to the monitor, if need be, setting
            also its dst mac address (first packet of flow) */
            /* WRITE YOUR CODE HERE */;
            Ethernet newEthPkt=ethPkt.duplicate();
            sendPktOut(monLocation.deviceId(), monLocation.port(), newEthPkt, monMac);
            /* if source and destination are on different switches, install mon flow objective
               to forward normal traffic along source->destination path, and then
               tag and forward traffic to 2nd switch along source -> monitor path */
            if (normLink.isPresent() && normPath.isPresent()) {
                /* WRITE YOUR CODE HERE */;
            }
            /* if source and destination are on same switch, install mon flow objective
               to forward normal traffic directly to destination,
               tag and forward traffic along source -> monitor path */
            else {
                /* WRITE YOUR CODE HERE */;
            }
            /* install link collection event for source->monitor path */
            /* WRITE YOUR CODE HERE */;
        }
    }

    /* NEW FUNCTIONS FOR fwdAndMonitor */
    /* WRITE YOUR CODE HERE */
    private void installForwardObjective(Host src,Host dst){
        TrafficSelector selector;
        TrafficTreatment treatment;
        Key key;

        selector=DefaultTrafficSelector.builder()
        .matchEthType(TYPE_IPV4)
        .matchIPSrc(src.ipAddresses().stream().findFirst().get().toIpPrefix())
        .matchIPDst(dst.ipAddresses().stream().findFirst().get().toIpPrefix())
        .build();

        treatment=DefaultTrafficTreatment.builder()
        .setOutput(dst.location().port())
        .build();

        ForwardingObjective forwardingObjective=DefaultForwardingObjective.builder()
        .withSelector(selector)
        .withTreatment(treatment)
        .withPriority(PRIORITY)
        .withFlag(ForwardingObjective.Flag.VERSATILE)
        .fromApp(appId)
        .add();

        flowObjectiveService.forward(dst.location().deviceId(), forwardingObjective);
        log.info("Installing flow objective = {}", forwardingObjective);
    }

    private void installLinkCollectionIntent(Host src, Host dst, Optional<Path> srcDstPath){
        TrafficSelector selector;
        TrafficTreatment treatment;
        Key key;

        selector=DefaultTrafficSelector.builder()
        .matchEthType(TYPE_IPV4)
        .matchIPSrc(src.ipAddresses().stream().findFirst().get().toIpPrefix())
        .matchIPDst(dst.ipAddresses().stream().findFirst().get().toIpPrefix())
        .build();

        treatment=DefaultTrafficTreatment.builder().build();

        Set<ConnectPoint> ingress = Sets.newConcurrentHashSet();
        Set<ConnectPoint> egress = Sets.newConcurrentHashSet();

        ingress.add(src.location());
        egress.add(dst.location());
        key=Key.of(src.toString()+'-'+ dst.toString(), appId);
        LinkCollectionIntent linkCollectionIntent=LinkCollectionIntent.builder()
        .appId(appId)
        .key(key)
        .selector(selector)
        .treatment(treatment)
        .links(Sets.newConcurrentHashSet(srcDstPath.get().links()))
        .applyTreatmentOnEgress(true)
        .ingressPoints(ingress)
        .egressPoints(egress)
        .priority(PRIORITY)
        .constraints(CONSTRAINTS)
        .build();

        intentSynchronizationService.submit(linkCollectionIntent);
        log.info("Installing Link Collection Intent={}", linkCollectionIntent);
    }
    /**
     * get only the monitored flows from the switch where the monitor is attached
     */
    @Override
    public Iterable<FlowEntry> getMonitorFlows() {
        Host host = getHost.apply(monitor);
        Iterable<FlowEntry> flowEntries =  flowStore.getFlowEntries(host.location().deviceId());
        List<FlowEntry> monFlowEntries = new ArrayList<FlowEntry>();
        flowEntries.forEach(
            flowEntry -> {
                // consider only IPv4 flow rules, with vlan=MON_VLAN
                /* WRITE YOUR CODE HERE */;     
             }
        );

        return monFlowEntries;
    }

    /**
     * Configuration event listener.
     */
    private class InternalNetworkConfigListener implements NetworkConfigListener {

        @Override
        public void event(NetworkConfigEvent event) {
            switch (event.type()) {
                case CONFIG_REGISTERED:
                case CONFIG_UNREGISTERED:
                    break;
                case CONFIG_ADDED:
                case CONFIG_UPDATED:
                case CONFIG_REMOVED:
                    if (event.configClass() == CONFIG_CLASS) {
                        Hy436Config config = (Hy436Config) event.config().orElseThrow(
                                () -> new RuntimeException("hy436 Config is null")
                        );
                        monitor = config.monitor();
                        monitoredHosts = config.monitoredHosts();
                        monitorDirection = config.monitorDirection();

                        discoverMonitors();
                    }
                    break;
                default:
                    break;
            }
        }
    }

    /**
     * Packet processor responsible for forwarding packets along their paths.
     */
    private class Hy436PacketProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {
            if (context.isHandled()) {
                return;
            }

            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            if (ethPkt == null) {
                return;
            }

            if (ethPkt.getEtherType() == TYPE_ARP) {
                HostId id = HostId.hostId(ethPkt.getDestinationMAC());
                Host dst = hostService.getHost(id);

                if (dst == null) {
                    flood(context);
                }
            } else if (ethPkt.getEtherType() == TYPE_IPV4) {
                IPv4 iPv4 = (IPv4) ethPkt.getPayload();
                IpAddress srcAddr = IpAddress.valueOf(iPv4.getSourceAddress()),
                        dstAddr = IpAddress.valueOf(iPv4.getDestinationAddress());

                // Ping to/from monitor is not accepted.
                if (!monitor.equals(srcAddr) && !monitor.equals(dstAddr)) {
                    Host sourceHost = getHost.apply(srcAddr),
                            destinationHost = getHost.apply(dstAddr);

                    // Check that the packet is received on a leaf switch.
                    if (sourceHost.location().deviceId().equals(context.inPacket().receivedFrom().deviceId())) {
                        fwdAndMonitor(sourceHost, destinationHost, ethPkt);
                    }
                } else {
                    log.warn("Pings from/to monitor are not accepted!");
                }
            }
        }

        /**
         * Flood a packet to all ports of a switch.
         *
         * @param context packet context
         */
        private void flood(PacketContext context) {
            if (topologyService.isBroadcastPoint(topologyService.currentTopology(),
                    context.inPacket().receivedFrom())) {
                context.treatmentBuilder().setOutput(PortNumber.FLOOD);
                context.send();
            } else {
                context.block();
            }
        }
    }
}
