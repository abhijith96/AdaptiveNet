package org.onosproject.ngsdn.tutorial;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.Triple;
import org.onlab.packet.Ip6Prefix;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.MacAddress;
import org.onlab.util.ItemNotFoundException;
import org.onosproject.net.*;
import org.onosproject.net.group.GroupDescription;
import org.onosproject.net.group.GroupService;
import org.onosproject.net.host.HostEvent;
import org.onosproject.net.host.HostListener;
import org.onosproject.net.host.HostService;
import org.onosproject.net.host.InterfaceIpAddress;
import org.onosproject.net.intf.Interface;
import org.onosproject.net.intf.InterfaceService;
import org.onosproject.net.link.LinkEvent;
import org.onosproject.net.link.LinkListener;
import org.onosproject.net.link.LinkService;


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


import com.google.common.collect.Lists;
import org.onlab.packet.Ip6Address;
import org.onosproject.core.ApplicationId;
import org.onosproject.mastership.MastershipService;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.device.DeviceEvent;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleOperations;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiActionParamId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.pi.runtime.PiActionProfileGroupId;
import org.onosproject.net.pi.runtime.PiTableAction;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.onosproject.ngsdn.tutorial.common.FabricDeviceConfig;
import org.onosproject.ngsdn.tutorial.common.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;
import java.util.stream.Collectors;

import static com.google.common.collect.Streams.mapWithIndex;
import static com.google.common.collect.Streams.stream;
import static org.onosproject.ngsdn.tutorial.AppConstants.INITIAL_SETUP_DELAY;
import static org.onosproject.ngsdn.tutorial.AppConstants.VLA_MAX_LEVELS;



/**
 * Application which handles VLA (Variable length addressing and level based routing)
 */
@Component(
        immediate = true,
        // *** TODO Research Project
        // set to true when ready
        enabled = true,
        service = VlaComponent.class
)
public class VlaComponent {

    class DeviceLevelPair{

        DeviceId deviceId;
        Integer level;

       public DeviceLevelPair(DeviceId deviceId, Integer level){
            this.deviceId = deviceId;
            this.level = level;
        }

        public DeviceId getDeviceId() {
            return deviceId;
        }

        public Integer GetLevel(){
           return level;
        }
    }

    private static final Logger log = LoggerFactory.getLogger(VlaComponent.class);

    //--------------------------------------------------------------------------
    // ONOS CORE SERVICE BINDING
    //
    // These variables are set by the Karaf runtime environment before calling
    // the activate() method.
    //--------------------------------------------------------------------------

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private MastershipService mastershipService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private GroupService groupService;


    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private LinkService linkService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private HostService hostService;


    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private InterfaceService interfaceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private NetworkConfigService networkConfigService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private MainComponent mainComponent;

    private final DeviceListener deviceListener = new VlaComponent.InternalDeviceListener();

    private final LinkListener linkListener = new VlaComponent.InternalLinkListener();

    private final HostListener hostListener = new VlaComponent.InternalHostListener();



    private ApplicationId appId;

    private HashMap<DeviceId, Integer> deviceLevelMap = new HashMap<>();

    private   HashMap<DeviceId, Integer>  deviceIdMap =  new HashMap<>();
    private  HashMap<DeviceId, ArrayList<DeviceId>>  parentMap = new HashMap<>();

    private  HashMap<DeviceId, ArrayList<DeviceId>>  childrenMap = new HashMap<>();





    private Optional<DeviceId> rootDeviceId  = Optional.empty();


    private final VlaTopologyInformation vlaTopologyInformation = new VlaTopologyInformation();


    private static final int DEFAULT_ECMP_GROUP_ID = 0xec3b0000;
    private static final long GROUP_INSERT_DELAY_MILLIS = 200;


    //--------------------------------------------------------------------------
    // COMPONENT ACTIVATION.
    //
    // When loading/unloading the app the Karaf runtime environment will call
    // activate()/deactivate().
    //--------------------------------------------------------------------------

    @Activate
    protected void activate() {
        appId = mainComponent.getAppId();

        vlaTopologyInformation.SetInterfaceService(this.interfaceService);

        // Register listeners to be informed about device and host events.
        deviceService.addListener(deviceListener);

        linkService.addListener(linkListener);

        hostService.addListener(hostListener);



        // Schedule set up for all devices.
        mainComponent.scheduleTask(this::setUpAllDevices, INITIAL_SETUP_DELAY);

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        deviceService.removeListener(deviceListener);
        linkService.removeListener(linkListener);
        hostService.removeListener(hostListener);
        deviceLevelMap.clear();
        parentMap.clear();
        childrenMap.clear();
        log.info("Stopped");
    }

    //--------------------------------------------------------------------------
    // METHODS TO COMPLETE.
    //
    // Complete the implementation wherever you see TODO.
    //--------------------------------------------------------------------------

    /**
     * Populate the My SID table from the network configuration for the
     * specified device.
     *
//     * @param  DeviceId device Id
     *
     */


    private int macToGroupId(MacAddress mac) {
        return mac.hashCode() & 0x7fffffff;
    }



    private void insertInOrder(GroupDescription group, Collection<FlowRule> flowRules) {
        try {
            groupService.addGroup(group);
            // Wait for groups to be inserted.
            Thread.sleep(GROUP_INSERT_DELAY_MILLIS);
            flowRules.forEach(flowRuleService::applyFlowRules);
        } catch (InterruptedException e) {
            log.error("Interrupted!", e);
            Thread.currentThread().interrupt();
        }
    }

    private GroupDescription createNextHopGroup(int groupId,
                                                Collection<MacAddress> nextHopMacs,
                                                DeviceId deviceId) {

        String actionProfileId = "IngressPipeImpl.ecmp_selector";

        final List<PiAction> actions = Lists.newArrayList();

        // Build one "set next hop" action for each next hop
        // *** TODO EXERCISE 5
        // Modify P4Runtime entity names to match content of P4Info file (look
        // for the fully qualified name of tables, match fields, and actions.
        // ---- START SOLUTION ----
        final String tableId = "IngressPipeImpl.routing_v6_table";
        for (MacAddress nextHopMac : nextHopMacs) {
            final PiAction action = PiAction.builder()
                    .withId(PiActionId.of("IngressPipeImpl.set_next_hop"))
                    .withParameter(new PiActionParam(
                            // Action param name.
                            PiActionParamId.of("next_hop_mac"),
                            // Action param value.
                            nextHopMac.toBytes()))
                    .build();

            actions.add(action);
        }
        // ---- END SOLUTION ----

        return Utils.buildSelectGroup(
                deviceId, tableId, actionProfileId, groupId, actions, appId);
    }

    private FlowRule createRoutingRule(DeviceId deviceId, Ip6Prefix ip6Prefix,
                                       int groupId) {

        // *** TODO EXERCISE 5
        // Modify P4Runtime entity names to match content of P4Info file (look
        // for the fully qualified name of tables, match fields, and actions.
        // ---- START SOLUTION ----
        final String tableId = "IngressPipeImpl.routing_v6_table";
        final PiCriterion match = PiCriterion.builder()
                .matchLpm(
                        PiMatchFieldId.of("hdr.ipv6.dst_addr"),
                        ip6Prefix.address().toOctets(),
                        ip6Prefix.prefixLength())
                .build();

        final PiTableAction action = PiActionProfileGroupId.of(groupId);
        // ---- END SOLUTION ----

        return Utils.buildFlowRule(
                deviceId, appId, tableId, match, action);
    }

    private boolean UpdateBasedOnLink(DeviceId source, DeviceId destination){

        Triple<ArrayList<VlaTopologyInformation.DeviceInfo>, ArrayList<VlaTopologyInformation.HostInfo>, HashMap<DeviceId, HashMap<Ip6Prefix, DeviceId>>> updates = vlaTopologyInformation.AddLink(source, destination);

        ArrayList<VlaTopologyInformation.DeviceInfo> deviceUpdates = updates.getLeft();
        for(VlaTopologyInformation.DeviceInfo deviceInfo : deviceUpdates){
            setUpCurrentLevelTable(deviceInfo.getDeviceId(), deviceInfo.GetLevel());
            setUpCurrentAddressTable(deviceInfo.getDeviceId(), deviceInfo.GetDeviceAddress());
            setUpParentTable(deviceInfo.GetParentId(), deviceInfo.getDeviceId(), deviceInfo.GetLevel());
            setUpChildTable(deviceInfo.GetParentId(), deviceInfo.getDeviceId(), deviceInfo.GetLevelIdentifier());
        }

        ArrayList<VlaTopologyInformation.HostInfo> hostUpdates = updates.getMiddle();

        for(VlaTopologyInformation.HostInfo hostInfo : hostUpdates){
            setUpChildHostTable(hostInfo.getDeviceId(), hostInfo.GetHostId(), hostInfo.getLevelIdentifier()) ;
            ArrayList<DeviceId> devicesContainingHosts = vlaTopologyInformation.GetAllDevicesContainingHosts();
            for(DeviceId deviceId: devicesContainingHosts){
                if(!isSpine(deviceId))
                    setUpHostNameResolutionTable(deviceId, hostInfo);
            }
        }

        HashMap<DeviceId, HashMap<Ip6Prefix, DeviceId>> ipRouteUpdates = updates.getRight();

        for(Map.Entry<DeviceId, HashMap<Ip6Prefix, DeviceId>>  entry : ipRouteUpdates.entrySet()){
            HashMap<Ip6Prefix, DeviceId> ipPrefixNextHopMap =   entry.getValue();
            DeviceId currentDevice = entry.getKey();
            for(Map.Entry<Ip6Prefix, DeviceId> subEntry : ipPrefixNextHopMap.entrySet()){
                Ip6Prefix ip6Prefix = subEntry.getKey();
                DeviceId nextHop = subEntry.getValue();

                final MacAddress nextHopMac = getMyStationMac(nextHop);
                final Set<Ip6Prefix> subnetsToRoute = new HashSet<Ip6Prefix>();
                subnetsToRoute.add(ip6Prefix);

                // Create a group with only one member.
                int groupId = macToGroupId(nextHopMac);
                GroupDescription group = createNextHopGroup(
                        groupId, Collections.singleton(nextHopMac), currentDevice);

                List<FlowRule> flowRules = subnetsToRoute.stream()
                        .map(subnet -> createRoutingRule(currentDevice, subnet, groupId))
                        .collect(Collectors.toList());

                insertInOrder(group, flowRules);
            }
        }

        return true;
    }

    private void UpdateDevice(DeviceId deviceId){

       Optional<VlaTopologyInformation.RootDeviceInfo>
        rootDeviceInfo = vlaTopologyInformation.AddDevice(deviceId, IsRootDevice(deviceId));
       if(rootDeviceInfo.isPresent()){
           setUpCurrentLevelTable(rootDeviceInfo.get().GetRootDeviceId(), rootDeviceInfo.get().GetLevel());
           setUpCurrentAddressTable(rootDeviceInfo.get().GetRootDeviceId(), rootDeviceInfo.get().GetVlaAddress());
       }
    }

    private void UpdateHost(Host host){
       ArrayList<VlaTopologyInformation.HostInfo> hostInfos =  vlaTopologyInformation.AddHost(host.id(), host.location().deviceId());
        for(VlaTopologyInformation.HostInfo hostInfo : hostInfos){
            setUpChildHostTable(hostInfo.getDeviceId(), hostInfo.GetHostId(), hostInfo.getLevelIdentifier()) ;
            ArrayList<DeviceId> devicesContainingHosts = vlaTopologyInformation.GetAllDevicesContainingHosts();
            for(DeviceId deviceId: devicesContainingHosts){
                if(!isSpine(deviceId))
                    setUpHostNameResolutionTable(deviceId, hostInfo);
            }
        }

    }

    private void setUpCurrentLevelTable(DeviceId deviceId, int level) {



        log.info("Adding current Level rule on {} )...", deviceId);


        // Fill in the table ID for the VLA current level table

        String tableId = "IngressPipeImpl.vla_level_table";

        // Modify the field and action id to match your P4Info
        // ---- START SOLUTION ----
        PiCriterion match = PiCriterion.builder()
                .matchExact(
                        PiMatchFieldId.of("hdr.vlah.current_level"),
                        level)
                .build();

        PiTableAction action = PiAction.builder()
                .withId(PiActionId.of("NoAction"))
                .build();
        // ---- END SOLUTION ----

        FlowRule myLevelRule = Utils.buildFlowRule(
                deviceId, appId, tableId, match, action);

        flowRuleService.applyFlowRules(myLevelRule);


    }

    private void setUpChildTable(DeviceId parent, DeviceId child, int childUniqueId) {


        log.info("Adding child table rule on device {} for child {} )...", parent, child);


        // Fill in the table ID for the VLA  route_to_child table
        // ---- START SOLUTION ----
        String tableId = "IngressPipeImpl.vla_route_children_table";




        // Modify the field and action id to match your P4Info
        // ---- START SOLUTION ----
        PiCriterion match = PiCriterion.builder()
                .matchExact(
                        PiMatchFieldId.of("local_metadata.vla_next_level_value"),childUniqueId
                        )
                .build();

        PiTableAction action = PiAction.builder()
                .withId(PiActionId.of("IngressPipeImpl.vla_route_to_child")).withParameter(
                        new PiActionParam(
                                PiActionParamId.of("target_mac"), getMyStationMac(child).toBytes()
                        )
                )
                .build();


        FlowRule routeToChildRule = Utils.buildFlowRule(
                parent, appId, tableId, match, action);

        flowRuleService.applyFlowRules(routeToChildRule);

    }

    private void setUpChildHostTable(DeviceId parent, HostId child, int hostUniqueId){
        log.info("Adding child table rule on device {} for child {} )...", parent, child);


        // Fill in the table ID for the VLA  route_to_child table
        // ---- START SOLUTION ----
        String tableId = "IngressPipeImpl.vla_route_children_table";




        // Modify the field and action id to match your P4Info
        // ---- START SOLUTION ----
        PiCriterion match = PiCriterion.builder()
                .matchExact(
                        PiMatchFieldId.of("local_metadata.vla_next_level_value"),hostUniqueId
                )
                .build();



        PiTableAction action = PiAction.builder()
                .withId(PiActionId.of("IngressPipeImpl.vla_route_to_child")).withParameter(
                        new PiActionParam(
                                PiActionParamId.of("target_mac"),  hostService.getHost(child).mac().toBytes()
                        )
                )
                .build();


        FlowRule routeToChildRule = Utils.buildFlowRule(
                parent, appId, tableId, match, action);

        flowRuleService.applyFlowRules(routeToChildRule);
    }

    private Pair<byte[], byte[]> DecodeVlaAddress(VlaTopologyInformation.HostInfo hostInfo){
       byte[] vlaAddress =   hostInfo.getHostAddress();

       byte[] vlaAddressPartOne = Arrays.copyOf(vlaAddress, 16);

       byte[] vlaAddressPartTwo = new byte[6];

        String binaryString = Integer.toBinaryString(hostInfo.getLevel());

       int bitCount = 8;

        // Left-pad the binary string with zeros to ensure it has the specified number of bits
        String paddedBinaryString = String.format("%" + bitCount + "s", binaryString).replace(' ', '0');
        System.out.println("paddes tring" +  paddedBinaryString);
        BigInteger bigInteger = new BigInteger(paddedBinaryString, 2);
        byte[] levelPortion = bigInteger.toByteArray();

        System.out.println("level portion length  " +  levelPortion.length);
        vlaAddressPartTwo[0] =  (byte)0xA0;
        vlaAddressPartTwo[1] =  levelPortion[0];
        for(int i = 16, index = 2; i < vlaAddress.length; ++i, ++index){
            vlaAddressPartTwo[index] = vlaAddress[i];
        }

        return Pair.of(vlaAddressPartOne, vlaAddressPartTwo);

    }




    private void setUpHostNameResolutionTable(DeviceId device, VlaTopologyInformation.HostInfo hostInfo){
        log.info("Adding Name Resolution Table in  {} for host {} )...", device, hostInfo.GetHostId());


        // Fill in the table ID for the VLA  route_to_child table
        // ---- START SOLUTION ----
        String tableId = "IngressPipeImpl.ndp_name_resolution_table";

        Pair<byte[], byte[]> vlaAddressPair = DecodeVlaAddress(hostInfo);


        // Modify the field and action id to match your P4Info
        // ---- START SOLUTION ----
        PiCriterion match = PiCriterion.builder()
                .matchExact(
                        PiMatchFieldId.of("hdr.ndp.target_mac_addr"),hostInfo.GetHostId().mac().toBytes()
                )
                .build();

        ArrayList<PiActionParam> paramList = new ArrayList<>();

        paramList.add(new PiActionParam(
                        PiActionParamId.of("device_mac"), getMyStationMac(device).toBytes()));

        paramList.add(new PiActionParam(
                PiActionParamId.of("target_vla_part_one"), vlaAddressPair.getLeft()));

        paramList.add(new PiActionParam(
                PiActionParamId.of("target_vla_part_two"), vlaAddressPair.getRight()));




        PiTableAction action = PiAction.builder()
                .withId(PiActionId.of("IngressPipeImpl.ndp_nr")).withParameters(
                        paramList)
                .build();


        FlowRule nameResolutionRule = Utils.buildFlowRule(
                device, appId, tableId, match, action);

        flowRuleService.applyFlowRules(nameResolutionRule);
    }

    private void setUpParentTable(DeviceId parent, DeviceId child, int childLevel) {


        log.info("Adding child table rule on device {} for child {} )...", parent, child);


        // Fill in the table ID for the VLA  route_to_child table
        // ---- START SOLUTION ----
        String tableId = "IngressPipeImpl.vla_route_to_parent_table";

        // Modify the field and action id to match your P4Info
        // ---- START SOLUTION ----
        PiCriterion match = PiCriterion.builder()
                .matchExact(
                        PiMatchFieldId.of("hdr.vlah.current_level"),childLevel
                )
                .build();

        PiTableAction action = PiAction.builder()
                .withId(PiActionId.of("IngressPipeImpl.vla_route_to_parent")).withParameter(
                        new PiActionParam(
                                PiActionParamId.of("target_mac"), getMyStationMac(parent).toBytes()
                        )
                )
                .build();


        FlowRule routeToParentRule = Utils.buildFlowRule(
                child, appId, tableId, match, action);

        flowRuleService.applyFlowRules(routeToParentRule);

    }

    private boolean setUpCurrentAddressTable(DeviceId deviceId, byte [] vlaAddress) {


        log.info("Adding current address table rule on device {})...", deviceId);

        // Fill in the table ID for the VLA  route_to_child table
        // ---- START SOLUTION ----
        String tableId = "IngressPipeImpl.current_vla_address_table";


        // Modify the field and action id to match your P4Info
        // ---- START SOLUTION ----
        PiCriterion match = PiCriterion.builder()
                .matchExact(
                        PiMatchFieldId.of("local_metadata.parser_local_metadata.destination_address_key"), vlaAddress
                )
                .build();

        PiTableAction action = PiAction.builder()
                .withId(PiActionId.of("NoAction"))
                .build();


        FlowRule currentAddressFlowRule = Utils.buildFlowRule(
                deviceId, appId, tableId, match, action);

        flowRuleService.applyFlowRules(currentAddressFlowRule);
        return true;

    }

    /**
     * Insert a SRv6 transit insert policy that will inject an SRv6 header for
     * packets destined to destIp.
     *
     * @param deviceId     device ID
     * @param destIp       target IP address for the SRv6 policy
     * @param prefixLength prefix length for the target IP
     * @param segmentList  list of SRv6 SIDs that make up the path
     */


    // ---------- END METHODS TO COMPLETE ----------------

    //--------------------------------------------------------------------------
    // EVENT LISTENERS
    //
    // Events are processed only if isRelevant() returns true.
    //--------------------------------------------------------------------------

    /**
     * Listener of device events.
     */
    public class InternalDeviceListener implements DeviceListener {

        @Override
        public boolean isRelevant(DeviceEvent event) {
            switch (event.type()) {
                case DEVICE_ADDED:
                case DEVICE_AVAILABILITY_CHANGED:
                    break;
                default:
                    // Ignore other events.
                    return false;
            }
            // Process only if this controller instance is the master.
            final DeviceId deviceId = event.subject().id();
            return mastershipService.isLocalMaster(deviceId);
        }

        @Override
        public void event(DeviceEvent event) {
            final DeviceId deviceId = event.subject().id();
            if (deviceService.isAvailable(deviceId)) {
                // A P4Runtime device is considered available in ONOS when there
                // is a StreamChannel session open and the pipeline
                // configuration has been set.
                mainComponent.getExecutorService().execute(() -> {
                    log.info("{} event! deviceId={}", event.type(), deviceId);

                    UpdateDevice(event.subject().id());
                });
            }
        }
    }



    class InternalLinkListener implements LinkListener {

        @Override
        public boolean isRelevant(LinkEvent event) {
            switch (event.type()) {
                case LINK_ADDED:
                    break;
                case LINK_UPDATED:
                case LINK_REMOVED:
                default:
                    return false;
            }
            DeviceId srcDev = event.subject().src().deviceId();
            DeviceId dstDev = event.subject().dst().deviceId();
            return mastershipService.isLocalMaster(srcDev) ||
                    mastershipService.isLocalMaster(dstDev);
        }

        @Override
        public void event(LinkEvent event) {
            DeviceId srcDev = event.subject().src().deviceId();
            DeviceId dstDev = event.subject().dst().deviceId();
            Link link = event.subject();

            if (mastershipService.isLocalMaster(srcDev) && mastershipService.isLocalMaster(dstDev)) {
                mainComponent.getExecutorService().execute(() -> {
                    log.info("{} event!  VLA Configuring {}... linkSrc={}, linkDst={}",
                            event.type(), srcDev, srcDev, dstDev);
                    UpdateBasedOnLink(srcDev, dstDev);
                });
            }
        }
    }

    public class InternalHostListener implements HostListener {

        @Override
        public boolean isRelevant(HostEvent event) {
            switch (event.type()) {
                case HOST_ADDED:
                    // Host added events will be generated by the
                    // HostLocationProvider by intercepting ARP/NDP packets.
                    break;
                case HOST_REMOVED:
                case HOST_UPDATED:
                case HOST_MOVED:
                default:
                    // Ignore other events.
                    // Food for thoughts: how to support host moved/removed?
                    return false;
            }
            // Process host event only if this controller instance is the master
            // for the device where this host is attached to.
            final Host host = event.subject();
            final DeviceId deviceId = host.location().deviceId();
            return mastershipService.isLocalMaster(deviceId);
        }

        @Override
        public void event(HostEvent event) {
            final Host host = event.subject();
            // Device and port where the host is located.
            final DeviceId deviceId = host.location().deviceId();
            final PortNumber port = host.location().port();

            mainComponent.getExecutorService().execute(() -> {
                log.info("{} event! host={}, deviceId={}, port={}",
                        event.type(), host.id(), deviceId, port);

                UpdateHost(host);
            });
        }
    }


    //--------------------------------------------------------------------------
    // UTILITY METHODS
    //--------------------------------------------------------------------------

    /**
     * Sets up SRv6 My SID table on all devices known by ONOS and for which this
     * ONOS node instance is currently master.
     */
    private synchronized void setUpAllDevices() {
        // Set up host routes
        stream(deviceService.getAvailableDevices())
                .map(Device::id)
                .filter(mastershipService::isLocalMaster)
                .forEach(deviceId -> {
                    log.info("*** Vla - Starting initial set up for {}...", deviceId);
                    this.UpdateDevice(deviceId);
                    hostService.getConnectedHosts(deviceId).forEach(
                            this::UpdateHost);
                });


    }

    /**
     * Returns the Srv6 config for the given device.
     *
     * @param deviceId the device ID
     * @return Srv6  device config
     */
    private Optional<FabricDeviceConfig> getDeviceConfig(DeviceId deviceId) {
        FabricDeviceConfig config = networkConfigService.getConfig(deviceId, FabricDeviceConfig.class);
        return Optional.ofNullable(config);
    }

    private boolean isSpine(DeviceId deviceId) {
        return getDeviceConfig(deviceId).map(FabricDeviceConfig::isSpine)
                .orElseThrow(() -> new ItemNotFoundException(
                        "Missing isSpine config for " + deviceId));
    }

    /**
     * Returns Srv6 SID for the given device.
     *
     * @param deviceId the device ID
     * @return SID for the device
     */
    private Ip6Address getMySid(DeviceId deviceId) {
        return getDeviceConfig(deviceId)
                .map(FabricDeviceConfig::mySid)
                .orElseThrow(() -> new RuntimeException(
                        "Missing mySid config for " + deviceId));
    }

    private MacAddress getMyStationMac(DeviceId deviceId) {
        return getDeviceConfig(deviceId)
                .map(FabricDeviceConfig::myStationMac)
                .orElseThrow(() -> new ItemNotFoundException(
                        "Missing myStationMac config for " + deviceId));
    }

    private boolean IsRootDevice(DeviceId deviceId){

        return getDeviceConfig(deviceId)
                .map(FabricDeviceConfig::isRoot)
                .orElseThrow(() -> new RuntimeException(
                        "Missing mySid config for " + deviceId));
    }

    private Set<Ip6Prefix> getInterfaceIpv6Prefixes(DeviceId deviceId) {
        return interfaceService.getInterfaces().stream()
                .filter(iface -> iface.connectPoint().deviceId().equals(deviceId))
                .map(Interface::ipAddressesList)
                .flatMap(Collection::stream)
                .map(InterfaceIpAddress::subnetAddress)
                .filter(IpPrefix::isIp6)
                .map(IpPrefix::getIp6Prefix)
                .collect(Collectors.toSet());
    }
}
