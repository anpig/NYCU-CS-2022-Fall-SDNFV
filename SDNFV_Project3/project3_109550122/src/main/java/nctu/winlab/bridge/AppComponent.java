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
package nctu.winlab.bridge;

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.Maps;
import org.onlab.packet.Ethernet;
import org.onlab.packet.MacAddress;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;

import java.util.Map;
import java.util.Optional;

@Component(immediate = true)
public class AppComponent {

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    private final Logger log = LoggerFactory.getLogger(getClass());

    protected Map<DeviceId, Map<MacAddress, PortNumber>> macTables = Maps.newConcurrentMap();
    private ApplicationId appId;
    private PacketProcessor bridgeProcessor;

    private int flowTimeout = 30;
    private int flowPriority = 30;

    @Activate
    protected void activate() {
        appId = coreService.getAppId("nctu.winlab.bridge");
        bridgeProcessor = new BridgePacketProcessor();
        packetService.addProcessor(bridgeProcessor, PacketProcessor.director(3));

        // process IPv4 and ARP packets only
        packetService.requestPackets(
            DefaultTrafficSelector.builder()
            .matchEthType(Ethernet.TYPE_IPV4).build(),
            PacketPriority.REACTIVE, appId, Optional.empty()
        );
        packetService.requestPackets(
            DefaultTrafficSelector.builder()
            .matchEthType(Ethernet.TYPE_ARP).build(),
            PacketPriority.REACTIVE, appId, Optional.empty()
        );
    }

    // deactivates the processor by removing it
    @Deactivate
    protected void deactivate() {
        packetService.removeProcessor(bridgeProcessor);
    }

    private class BridgePacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext pc) {
            if (pc.isHandled()) {
                return;
            }
            macTables.putIfAbsent(pc.inPacket().receivedFrom().deviceId(), Maps.newConcurrentMap());
            InboundPacket packet = pc.inPacket();
            Ethernet frame = packet.parsed();
            if (frame.getEtherType() != Ethernet.TYPE_IPV4 && frame.getEtherType() != Ethernet.TYPE_ARP) {
                return;
            }

            // learn
            ConnectPoint cp = packet.receivedFrom();
            Map<MacAddress, PortNumber> macTable = macTables.get(cp.deviceId());
            MacAddress src = frame.getSourceMAC(), dest = frame.getDestinationMAC();
            PortNumber outPort = macTable.get(dest);
            macTable.put(src, cp.port());
            log.info(
                "Add an entry to the port table of `{}`. MAC address: `{}` => Port `{}`.",
                cp.deviceId().toString(), src.toString(), macTable.get(src).toString()
            );

            if (outPort != null) { // learned
                pc.treatmentBuilder().setOutput(outPort);
                FlowRule rule = DefaultFlowRule.builder()
                    .withSelector(
                        DefaultTrafficSelector.builder()
                        .matchEthDst(dest).build()
                    )
                    .withTreatment(
                        DefaultTrafficTreatment.builder()
                        .setOutput(outPort).build()
                    )
                    .forDevice(cp.deviceId())
                    .withPriority(flowPriority)
                    .makeTemporary(flowTimeout)
                    .fromApp(appId).build();

                flowRuleService.applyFlowRules(rule);
                pc.send();
                log.info(
                    "MAC address `{}` is matched on `{}`. Install a flow rule.",
                    dest.toString(), cp.deviceId().toString()
                );
            } else { // not learned
                pc.treatmentBuilder().setOutput(PortNumber.FLOOD);
                pc.send();
                log.info(
                    "MAC address `{}` is missed on `{}`. Flood the packet.",
                    dest.toString(), cp.deviceId().toString()
                );
            }
        }
    }
}