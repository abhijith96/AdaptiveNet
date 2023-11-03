package org.onosproject.ngsdn.tutorial;
import com.sun.source.tree.Tree;
import org.apache.commons.lang3.tuple.Pair;
import org.onosproject.net.Link;
import org.onosproject.net.link.LinkService;
import org.onosproject.store.primitives.DefaultConsistentMap;
import org.onosproject.store.primitives.DefaultConsistentTreeMap;
import org.onosproject.store.service.AsyncAtomicValue;
import org.onosproject.net.ConnectPoint;

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
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
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

import java.util.*;

import static com.google.common.collect.Streams.stream;
import static org.onosproject.ngsdn.tutorial.AppConstants.INITIAL_SETUP_DELAY;



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

        // Schedule set up for all devices.
        mainComponent.scheduleTask(this::setUpAllDevices, INITIAL_SETUP_DELAY);

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        deviceService.removeListener(deviceListener);
        deviceLevelMap.clear();
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
    private void DoDfsFromRoot(DeviceId rootDeviceId){
        HashMap<DeviceId, Integer> visitedDeviceLevelMap = new HashMap<>();
        Queue<DeviceLevelPair> deviceIdQueue = new LinkedList<>();
       deviceIdQueue.add(new DeviceLevelPair(rootDeviceId, 1));

        while(!deviceIdQueue.isEmpty()){
            DeviceId currentDevice = deviceIdQueue.peek().getDeviceId();
            Integer currentLevel = deviceIdQueue.peek().GetLevel();
            visitedDeviceLevelMap.put(currentDevice, currentLevel);
            deviceLevelMap.put(currentDevice, currentLevel);
            deviceIdQueue.remove();
            Iterable<Link> deviceLinks = linkService.getDeviceLinks(currentDevice);
            for (Link link : deviceLinks) {
                if(link.src().elementId() instanceof  DeviceId && link.dst().elementId() instanceof DeviceId){
                    if(link.src().deviceId() == currentDevice){
                        DeviceId dst = link.dst().deviceId();
                        if(!visitedDeviceLevelMap.containsKey(dst)){
                            deviceIdQueue.add(new DeviceLevelPair(dst, currentLevel + 1));
                            if(childrenMap.containsKey(currentDevice)){
                                childrenMap.get(currentDevice).add(dst);
                            }
                            else{
                                childrenMap.put(currentDevice, new ArrayList<>());
                                childrenMap.get(currentDevice).add(dst);
                            }
                            parentMap.put(dst, new ArrayList<>());
                            parentMap.get(dst).add(currentDevice);
                        }
                        else{
                            DeviceId previousParent = parentMap.get(dst).get(0);
                            if(Objects.equals(visitedDeviceLevelMap.get(previousParent), currentLevel)){
                                parentMap.get(dst).add(currentDevice);
                            }
                        }
                    }
                }
            }
        }

    }

    private void setUpMySidTable(DeviceId deviceId) {

        Ip6Address mySid = getMySid(deviceId);

        log.info("Adding current Level rule on {} (vla {})...", deviceId, mySid);

        // *** TODO EXERCISE 6
        // Fill in the table ID for the SRv6 my segment identifier table
        // ---- START SOLUTION ----
        String tableId = "IngressPipeImpl.vla_level_table";

        int tempLevel = 10;
        if(IsRootDevice(deviceId)) {
            log.info("Found Vla root Device {}", deviceId);
           if(!deviceLevelMap.containsKey(deviceId)){
               rootDeviceId = Optional.of(deviceId);
               DoDfsFromRoot(deviceId);
           }
           tempLevel = deviceLevelMap.get(deviceId);
        }
        else {
            if(rootDeviceId.isPresent()){
                log.info("VLa Tree Map is Persistent", deviceId);
            }
        }






        // ---- END SOLUTION ----

        // *** TODO EXERCISE 6
        // Modify the field and action id to match your P4Info
        // ---- START SOLUTION ----
        PiCriterion match = PiCriterion.builder()
                .matchExact(
                        PiMatchFieldId.of("hdr.vlah.current_level"),
                        tempLevel)
                .build();

        PiTableAction action = PiAction.builder()
                .withId(PiActionId.of("NoAction"))
                .build();
        // ---- END SOLUTION ----

        FlowRule myLevelRule = Utils.buildFlowRule(
                deviceId, appId, tableId, match, action);

        flowRuleService.applyFlowRules(myLevelRule);
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

                    setUpMySidTable(event.subject().id());
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
                    log.info("*** SRV6 - Starting initial set up for {}...", deviceId);
                    this.setUpMySidTable(deviceId);
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

    private boolean IsRootDevice(DeviceId deviceId){

        return getDeviceConfig(deviceId)
                .map(FabricDeviceConfig::isRoot)
                .orElseThrow(() -> new RuntimeException(
                        "Missing mySid config for " + deviceId));
    }
}
