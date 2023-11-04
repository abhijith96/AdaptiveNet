package org.onosproject.ngsdn.tutorial;
import com.sun.source.tree.Tree;
import org.apache.commons.lang3.tuple.Pair;
import org.onlab.packet.MacAddress;
import org.onlab.util.ItemNotFoundException;
import org.onosproject.net.*;
import org.onosproject.net.link.LinkEvent;
import org.onosproject.net.link.LinkListener;
import org.onosproject.net.link.LinkService;
import org.onosproject.store.primitives.DefaultConsistentMap;
import org.onosproject.store.primitives.DefaultConsistentTreeMap;
import org.onosproject.store.service.AsyncAtomicValue;

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

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

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
    private LinkService linkService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private NetworkConfigService networkConfigService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private MainComponent mainComponent;

    private final DeviceListener deviceListener = new VlaComponent.InternalDeviceListener();

    private final LinkListener linkListener = new VlaComponent.InternalLinkListener();



    private ApplicationId appId;

    private HashMap<DeviceId, Integer> deviceLevelMap = new HashMap<>();

    private   HashMap<DeviceId, Integer>  deviceIdMap =  new HashMap<>();
    private  HashMap<DeviceId, ArrayList<DeviceId>>  parentMap = new HashMap<>();

    private  HashMap<DeviceId, ArrayList<DeviceId>>  childrenMap = new HashMap<>();



    private Optional<DeviceId> rootDeviceId  = Optional.empty();





    //--------------------------------------------------------------------------
    // COMPONENT ACTIVATION.
    //
    // When loading/unloading the app the Karaf runtime environment will call
    // activate()/deactivate().
    //--------------------------------------------------------------------------

    @Activate
    protected void activate() {
        appId = mainComponent.getAppId();

        // Register listeners to be informed about device and host events.
        deviceService.addListener(deviceListener);

        linkService.addListener(linkListener);

        // Schedule set up for all devices.
        mainComponent.scheduleTask(this::setUpAllDevices, INITIAL_SETUP_DELAY);

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        deviceService.removeListener(deviceListener);
        linkService.removeListener(linkListener);
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

    private boolean UpdateBasedOnLink(DeviceId source, DeviceId destination){
        if(!deviceIdMap.containsKey(source) && !deviceLevelMap.containsKey(destination)){
            return false;
        }
        if(deviceLevelMap.containsKey(source) && deviceLevelMap.containsKey(destination)){
            return false;
        }
        if(deviceLevelMap.containsKey(source)){
            log.info("Update based on link VLA source part of level tree, linkSrc={}, linkDst={}", source, destination);
            deviceLevelMap.put(destination, deviceLevelMap.get(source) + 1);
            if(!childrenMap.containsKey(source)){
                childrenMap.put(source, new ArrayList<>());
            }
            childrenMap.get(source).add(destination);
            if(!parentMap.containsKey(destination)){
                parentMap.put(destination, new ArrayList<>());
            }
            parentMap.get(destination).add(source);
            setUpChildTable(source, destination);
            setUpParentTable(source, destination, deviceLevelMap.get(source) + 1);
            DoBfs(destination, deviceLevelMap.get(source) + 1);
            return true;
        }
        else if(deviceLevelMap.containsKey(destination)){
            log.info("Update based on link VLA destination part of level tree, linkSrc={}, linkDst={}", source, destination);
                DeviceId temp = source;
                source = destination;
                destination = temp;
                deviceLevelMap.put(destination, deviceLevelMap.get(source) + 1);
                if(!childrenMap.containsKey(source)){
                    childrenMap.put(source, new ArrayList<>());
                }
                childrenMap.get(source).add(destination);
                if(!parentMap.containsKey(destination)){
                    parentMap.put(destination, new ArrayList<>());
                }
                parentMap.get(destination).add(source);
                setUpChildTable(source, destination);
                setUpParentTable(source, destination, deviceLevelMap.get(source) + 1);
                DoBfs(destination, deviceLevelMap.get(source) + 1);
                return true;
        }
        return false;
    }

    private void UpdateDevice(DeviceId deviceId){
        if(IsRootDevice(deviceId)){
            log.info("Adding Level rule on root device {} )...", deviceId);
            rootDeviceId = Optional.of(deviceId);
            setUpCurrentLevelTable(deviceId, 1);
            deviceIdMap.put(deviceId, 1);
            DoBfsFromRoot(deviceId);
        }
    }

    Optional<byte[]> GetVlaAddress(DeviceId deviceId){


        if(deviceLevelMap.containsKey(deviceId)){
            int deviceLevel = deviceLevelMap.get(deviceId);
            short[] vlaAddress = new short[VLA_MAX_LEVELS];
            int currentLevel = deviceLevel;
            DeviceId currentDevice = deviceId;
            while(currentLevel > 0){
                DeviceId parentDevice =  currentLevel > 1 ? parentMap.get(currentDevice).get(0) : null;
                int currentLevelAddress = parentDevice != null ? childrenMap.get(parentDevice).indexOf(currentDevice) + 1 : 1;
                vlaAddress[currentLevel - 1] = (short) currentLevelAddress;
                currentDevice = parentDevice;
                --currentLevel;
            }
            ByteBuffer buffer = ByteBuffer.allocate(vlaAddress.length * 2);
            buffer.order(ByteOrder.BIG_ENDIAN);
            buffer.asShortBuffer().put(vlaAddress);
            byte[] byteArray = buffer.array();
            return Optional.of(byteArray);

        }
        return Optional.empty();
    }

    private void DoBfs(DeviceId deviceId, int level){
        HashMap<DeviceId, Integer> visitedDeviceLevelMap = new HashMap<>();
        Queue<DeviceLevelPair> deviceIdQueue = new LinkedList<>();
        deviceIdQueue.add(new DeviceLevelPair(deviceId, level));

        while(!deviceIdQueue.isEmpty()){
            DeviceId currentDevice = deviceIdQueue.peek().getDeviceId();
            Integer currentLevel = deviceIdQueue.peek().GetLevel();
            visitedDeviceLevelMap.put(currentDevice, currentLevel);
            deviceLevelMap.put(currentDevice, currentLevel);
            setUpCurrentLevelTable(deviceId, currentLevel);
            setUpCurrentAddressTable(currentDevice);
            deviceIdQueue.remove();
            Iterable<Link> deviceLinks = linkService.getDeviceLinks(currentDevice);
            for (Link link : deviceLinks) {
                if(link.src().elementId() instanceof  DeviceId && link.dst().elementId() instanceof DeviceId){
                    if(link.src().deviceId() == currentDevice){
                        DeviceId dst = link.dst().deviceId();
                        if(!visitedDeviceLevelMap.containsKey(dst) && !deviceLevelMap.containsKey(dst)){
                            deviceIdQueue.add(new DeviceLevelPair(dst, currentLevel + 1));
                            if(childrenMap.containsKey(currentDevice)){
                                childrenMap.get(currentDevice).add(dst);
                            }
                            else{
                                childrenMap.put(currentDevice, new ArrayList<>());
                                childrenMap.get(currentDevice).add(dst);
                            }
                            setUpChildTable(currentDevice, dst);
                            parentMap.put(dst, new ArrayList<>());
                            parentMap.get(dst).add(currentDevice);
                            setUpParentTable(currentDevice, dst, currentLevel + 1);
                        }
                        else if(parentMap.containsKey(dst)){
                            DeviceId previousParent = parentMap.get(dst).get(0);
                            if(previousParent != link.src().deviceId() && Objects.equals(visitedDeviceLevelMap.get(previousParent), currentLevel)){
                                parentMap.get(dst).add(currentDevice);
                            }
                        }
                    }
                }
            }
        }

    }
    private void DoBfsFromRoot(DeviceId rootDeviceId){
        HashMap<DeviceId, Integer> visitedDeviceLevelMap = new HashMap<>();
        Queue<DeviceLevelPair> deviceIdQueue = new LinkedList<>();
       deviceIdQueue.add(new DeviceLevelPair(rootDeviceId, 1));

        while(!deviceIdQueue.isEmpty()){
            DeviceId currentDevice = deviceIdQueue.peek().getDeviceId();
            Integer currentLevel = deviceIdQueue.peek().GetLevel();
            visitedDeviceLevelMap.put(currentDevice, currentLevel);
            deviceLevelMap.put(currentDevice, currentLevel);
            setUpCurrentLevelTable(currentDevice, currentLevel);
            setUpCurrentAddressTable(currentDevice);
            deviceIdQueue.remove();
            Iterable<Link> deviceLinks = linkService.getDeviceLinks(currentDevice);
            for (Link link : deviceLinks) {
                if(link.src().elementId() instanceof  DeviceId && link.dst().elementId() instanceof DeviceId){
                    if(link.src().deviceId() == currentDevice){
                        DeviceId dst = link.dst().deviceId();
                        if(!visitedDeviceLevelMap.containsKey(dst)){
                            deviceIdQueue.add(new DeviceLevelPair(dst, currentLevel + 1));
                            if(childrenMap.containsKey(currentDevice)){
                                if(!childrenMap.get(currentDevice).contains(dst))
                                    childrenMap.get(currentDevice).add(dst);
                            }
                            else{
                                childrenMap.put(currentDevice, new ArrayList<>());
                                childrenMap.get(currentDevice).add(dst);
                            }
                            setUpChildTable(currentDevice, dst);
                            parentMap.put(dst, new ArrayList<>());
                            parentMap.get(dst).add(currentDevice);
                            setUpParentTable(currentDevice, dst, currentLevel + 1);
                        }
                        else{
                            DeviceId previousParent = parentMap.get(dst).get(0);
                            if(Objects.equals(visitedDeviceLevelMap.get(previousParent), currentLevel) && !parentMap.get(dst).contains(currentDevice)){
                                parentMap.get(dst).add(currentDevice);
                            }
                        }
                    }
                }
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

    private void setUpChildTable(DeviceId parent, DeviceId child) {


        log.info("Adding child table rule on device {} for child {} )...", parent, child);


        // Fill in the table ID for the VLA  route_to_child table
        // ---- START SOLUTION ----
        String tableId = "IngressPipeImpl.vla_route_children_table";

        int childUniqueId = childrenMap.get(parent).indexOf(child) + 1;


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

    private boolean setUpCurrentAddressTable(DeviceId deviceId) {

        Optional<byte[]> currentAddress = GetVlaAddress(deviceId);

        if (currentAddress.isPresent()) {

        log.info("Adding current address table rule on device {})...", deviceId);


        // Fill in the table ID for the VLA  route_to_child table
        // ---- START SOLUTION ----
        String tableId = "IngressPipeImpl.current_vla_address_table";

        // Modify the field and action id to match your P4Info
        // ---- START SOLUTION ----
        PiCriterion match = PiCriterion.builder()
                .matchExact(
                        PiMatchFieldId.of("local_metadata.parser_local_metadata.destination_address_key"), currentAddress.get()
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
        return false;

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
//    public void insertSrv6InsertRule(DeviceId deviceId, Ip6Address destIp, int prefixLength,
//                                     List<Ip6Address> segmentList) {
//        if (segmentList.size() < 2 || segmentList.size() > 3) {
//            throw new RuntimeException("List of " + segmentList.size() + " segments is not supported");
//        }
//
//        // *** TODO EXERCISE 6
//        // Fill in the table ID for the SRv6 transit table.
//        // ---- START SOLUTION ----
//        String tableId = "IngressPipeImpl.srv6_transit";
//        // ---- END SOLUTION ----
//
//        // *** TODO EXERCISE 6
//        // Modify match field, action id, and action parameters to match your P4Info.
//        // ---- START SOLUTION ----
//        PiCriterion match = PiCriterion.builder()
//                .matchLpm(PiMatchFieldId.of("hdr.ipv6.dst_addr"), destIp.toOctets(), prefixLength)
//                .build();
//
//        List<PiActionParam> actionParams = Lists.newArrayList();
//
//        for (int i = 0; i < segmentList.size(); i++) {
//            PiActionParamId paramId = PiActionParamId.of("s" + (i + 1));
//            PiActionParam param = new PiActionParam(paramId, segmentList.get(i).toOctets());
//            actionParams.add(param);
//        }
//
//        PiAction action = PiAction.builder()
//                .withId(PiActionId.of("IngressPipeImpl.srv6_t_insert_" + segmentList.size()))
//                .withParameters(actionParams)
//                .build();
//        // ---- END SOLUTION ----
//
//        final FlowRule rule = Utils.buildFlowRule(
//                deviceId, appId, tableId, match, action);
//
//        flowRuleService.applyFlowRules(rule);
//    }
//
//    /**
//     * Remove all SRv6 transit insert polices for the specified device.
//     *
//     * @param deviceId device ID
//     */
//    public void clearSrv6InsertRules(DeviceId deviceId) {
//        // *** TODO EXERCISE 6
//        // Fill in the table ID for the SRv6 transit table
//        // ---- START SOLUTION ----
//        String tableId = "IngressPipeImpl.srv6_transit";
//        // ---- END SOLUTION ----
//
//        FlowRuleOperations.Builder ops = FlowRuleOperations.builder();
//        stream(flowRuleService.getFlowEntries(deviceId))
//                .filter(fe -> fe.appId() == appId.id())
//                .filter(fe -> fe.table().equals(PiTableId.of(tableId)))
//                .forEach(ops::remove);
//        flowRuleService.apply(ops.build());
//    }

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
}
