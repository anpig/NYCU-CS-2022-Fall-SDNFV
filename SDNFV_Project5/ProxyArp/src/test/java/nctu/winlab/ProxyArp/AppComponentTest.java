/*
 * Copyright 2022-present Open Networking Foundation
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
package nctu.winlab.ProxyArp;

import org.onlab.packet.Ethernet;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.MacAddress;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.Maps;

import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.edge.EdgePortService;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;

import java.nio.ByteBuffer;
import java.util.Map;

import org.onlab.packet.ARP;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)
public class AppComponentTest {

    private final Logger log = LoggerFactory.getLogger(getClass());
    private ApplicationId appId; 
    private Map<Ip4Address, MacAddress> macTable = Maps.newConcurrentMap();
    private Map<MacAddress, ConnectPoint> cpTable = Maps.newConcurrentMap();
    private ProxyArpProcessor processor = new ProxyArpProcessor();

    // @Reference(cardinality = ReferenceCardinality.MANDATORY)
    // protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected EdgePortService edgePortService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("nctu.winlab.ArpProxy");
        packetService.addProcessor(processor, PacketProcessor.director(3));
        packetService.requestPackets(
            DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_ARP)
                .build(),
            PacketPriority.REACTIVE,
            appId
        );
    }

    @Deactivate
    protected void deactivate() {
        packetService.removeProcessor(processor);
        macTable.clear();
        cpTable.clear();
    }

    private class ProxyArpProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            if (context.isHandled() || context.inPacket().parsed().getEtherType() != Ethernet.TYPE_ARP) return;

            ConnectPoint cp = context.inPacket().receivedFrom();
            Ethernet etherFrame = context.inPacket().parsed();
            ARP arpPacket = (ARP)etherFrame.getPayload();

            macTable.putIfAbsent(Ip4Address.valueOf(arpPacket.getSenderProtocolAddress()), etherFrame.getSourceMAC());
            cpTable.putIfAbsent(etherFrame.getSourceMAC(), cp);

            if (arpPacket.getOpCode() == ARP.OP_REQUEST) {
                MacAddress requestMacAddress = macTable.get(Ip4Address.valueOf(arpPacket.getTargetProtocolAddress()));
                if (requestMacAddress == null) {
                    for (ConnectPoint iterCp : edgePortService.getEdgePoints()) {
                        if (iterCp == cp) continue;
                        OutboundPacket outboundPacket = new DefaultOutboundPacket(
                            iterCp.deviceId(),
                            DefaultTrafficTreatment.builder()
                                .setOutput(iterCp.port())
                                .build(),
                            ByteBuffer.wrap(etherFrame.serialize())
                        );
                        packetService.emit(outboundPacket);
                        log.info("TABLE MISS. Send request to edge ports");
                    }
                }
                else {
                    // Ethernet Packet
                    Ethernet replyFrame = ARP.buildArpReply(Ip4Address.valueOf(arpPacket.getTargetProtocolAddress()), etherFrame.getSourceMAC(), etherFrame);
                    
                    // add Traffic Treatment and emit
                    OutboundPacket outPacket = new DefaultOutboundPacket(
                        cp.deviceId(),
                        DefaultTrafficTreatment.builder().setOutput(cp.port()).build(),
                        ByteBuffer.wrap(replyFrame.serialize())
                    );
                    packetService.emit(outPacket);
                    log.info("TABLE HIT. Requested MAC = {}", requestMacAddress.toString());
                }
            }
            else if (arpPacket.getOpCode() == ARP.OP_REPLY) {
                log.info("RECV REPLY. Requested MAC = {}", MacAddress.valueOf(arpPacket.getSenderHardwareAddress()).toString());
            }
        }
    }
}
