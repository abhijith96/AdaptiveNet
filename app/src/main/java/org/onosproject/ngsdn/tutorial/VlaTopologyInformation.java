package org.onosproject.ngsdn.tutorial;

import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.*;

import org.apache.commons.lang3.tuple.Pair;


public class VlaTopologyInformation {

    private final int IDENTIFIER_START_VALUE = 4096;
    ArrayList<DeviceId> deviceList;
    ArrayList<DeviceId> rootDeviceList;

   HashMap<DeviceId, Integer> deviceChildIdentifierCounter;

   HashMap<DeviceId, ArrayList<DeviceId>> deviceNeighbours;

   HashMap<DeviceId, Boolean> IsConnectedToRoot;

   HashMap<DeviceId, HashMap<DeviceId, Integer>> childrenMap;

   HashMap<DeviceId,  DeviceId> parentMap;
   HashMap<DeviceId, Integer> levelMap;

   HashMap<DeviceId, Integer> deviceIdentifierMap;

   HashMap<DeviceId, ArrayList<HostId>> deviceIdHostIdHashMap;

   HashMap<HostId, DeviceId> hostIdDeviceIdHashMap;

    private static final Logger log = LoggerFactory.getLogger(VlaTopologyInformation.class);

    public class DeviceInfo{

        private DeviceId deviceId;

        private DeviceId parentId;
        private Integer level;

        private  Integer levelIdentifier;

        byte[] deviceAddress;

        public DeviceInfo(DeviceId deviceId, DeviceId parentId, Integer level){
            this.deviceId = deviceId;
            this.parentId = parentId;
            this.level = level;
            this.levelIdentifier = 0;
        }

        public DeviceId getDeviceId() {
            return deviceId;
        }



        public Integer GetLevel(){
            return level;
        }

        public DeviceId GetParentId() {
            return parentId;
        }


        /**
         * Unique Address for device in parent's address space
         * @param levelIdentifier
         */
        public void SetLevelIdentifier(int levelIdentifier){
            this.levelIdentifier = levelIdentifier;
        }

        public void SetDeviceAddress(byte[] deviceAddress){
            this.deviceAddress = deviceAddress;
        }

        public int GetLevelIdentifier(){
            return levelIdentifier;
        }

        public byte[] GetDeviceAddress(){
            return deviceAddress;
        }
    };

    public class HostInfo{
        private HostId hostId;
        private DeviceId deviceId;

        private  int level;

        public DeviceId getDeviceId() {
            return deviceId;
        }

        public int getLevel() {
            return level;
        }

        /**
         * Unique Address for host in parent's address space
         */
        public int getLevelIdentifier() {
            return levelIdentifier;
        }

        public byte[] getHostAddress() {
            return hostAddress;
        }

        private int levelIdentifier;

        private byte[] hostAddress;

        public HostInfo (HostId hostId, DeviceId deviceId) {
            this.hostId = hostId;
            this.deviceId = deviceId;
            this.level = levelMap.get(deviceId) + 1;
            int identifier = deviceChildIdentifierCounter.get(deviceId);
            deviceChildIdentifierCounter.put(deviceId, identifier + 1);
            this.levelIdentifier = identifier;

            byte[] deviceAddress = GetVlaAddress(deviceId, this.level - 1);

            String hostAddressString = String.format("%16s", Integer.toBinaryString(this.levelIdentifier)).replace(' ', '0');
            BigInteger bigInteger = new BigInteger(hostAddressString, 2);
            byte[] hostPortion = bigInteger.toByteArray();
            deviceAddress[2 * (this.level - 1)] = hostPortion[0];
            deviceAddress[(2 * (this.level - 1)) + 1] = hostPortion[1];
            hostAddress = deviceAddress;
        }
        public HostId GetHostId() { return hostId; }
    }

    public class RootDeviceInfo{
        private DeviceId rootDeviceId;
       private  int level;
       private int levelIdentifier;

       private byte[] deviceAddress;

        public RootDeviceInfo(DeviceId rootDeviceId, int levelIdentifier){
            this.rootDeviceId = rootDeviceId;
            this.level = 1;
            this.levelIdentifier = levelIdentifier;
        }

        public DeviceId GetRootDeviceId(){
            return rootDeviceId;
        }

        public int GetLevel(){
            return level;
        }
        public int GetLevelIdentifier(){
            return levelIdentifier;
        }

        void SetVlaAddress(byte[] vlaAddress){
            deviceAddress = vlaAddress;
        }

        public byte[] GetVlaAddress(){
            return deviceAddress;
        }


    }


   public VlaTopologyInformation(){
       deviceList = new ArrayList<>();
       rootDeviceList = new ArrayList<>();
       deviceChildIdentifierCounter = new HashMap<>();
       deviceNeighbours = new HashMap<>();
       childrenMap = new HashMap<>();
       parentMap = new HashMap<>();
       levelMap = new HashMap<>();
       IsConnectedToRoot = new HashMap<>();
       deviceIdentifierMap = new HashMap<>();
       deviceIdHostIdHashMap = new HashMap<>();
       hostIdDeviceIdHashMap = new HashMap<>();
   }

   private Integer GetIdentifier(DeviceId deviceId){
       if(deviceIdentifierMap.containsKey(deviceId)){
           return deviceIdentifierMap.get(deviceId);
       }
       return -1;
   }

   private int AddChild(DeviceId parent, DeviceId child){
       int identifier = deviceChildIdentifierCounter.get(parent);
       deviceChildIdentifierCounter.put(parent, identifier + 1);
       if(!childrenMap.containsKey(parent)){
           childrenMap.put(parent, new HashMap<>());
       }
       childrenMap.get(parent).put(child, identifier);
       return identifier;
   }




    private byte [] ConvertBitStringArrayToByteArray(String[] VlaAddressInBitStrings){

        int bitShift = AppConstants.VLA_LEVEL_BITS/ 2;

        StringBuilder stringBuilder = new StringBuilder();

        for (String value : VlaAddressInBitStrings){
            stringBuilder.append(value);
        }
        String bigString = stringBuilder.toString();
        BigInteger bigInteger = new BigInteger(bigString, 2);
        byte[] byteArray =  bigInteger.toByteArray();
        return byteArray;
    }



  private byte [] GetVlaAddress(DeviceId deviceId, int deviceLevel){
       String [] vlaAddress = new String [AppConstants.VLA_MAX_LEVELS];
      log.info("Finding Levels up the tree. {}", deviceId);
       int currentLevel = deviceLevel;
       DeviceId currentDevice = deviceId;
       while(currentLevel > 0){
           int currentLevelAddress =  deviceIdentifierMap.get(currentDevice);
           vlaAddress [currentLevel - 1] = String.format("%16s", Integer.toBinaryString(currentLevelAddress)).replace(' ', '0');
           log.info("Finding levels current device {}, current Level {} address {}, address bit string {} ", currentDevice, currentLevel, currentLevelAddress,
                   vlaAddress [currentLevel - 1]);
           --currentLevel;
           currentDevice = parentMap.getOrDefault(currentDevice, null);
       }
       for(currentLevel = deviceLevel + 1; currentLevel <= AppConstants.VLA_MAX_LEVELS; ++currentLevel){
           int val = 0;
           String addressSuffix =  String.format("%16s", Integer.toBinaryString(val)).replace(' ', '0');
           vlaAddress[currentLevel - 1] = addressSuffix;
       }
       return ConvertBitStringArrayToByteArray(vlaAddress);
   }

   private  Pair<ArrayList<DeviceInfo>, ArrayList<HostInfo>> DoTraversal(DeviceId parent, DeviceId firstChild, Integer parentLevel){
       Queue<DeviceInfo> queue = new LinkedList<>();
       queue.add(new DeviceInfo(firstChild, parent, parentLevel + 1));

       ArrayList<DeviceInfo> results = new ArrayList<>();

       ArrayList<HostInfo> hostResults = new ArrayList<>();

       HashSet<DeviceId> visited = new HashSet<>();
       visited.add(parent);

       while(!queue.isEmpty()){
           DeviceInfo deviceInfo = queue.peek();
           DeviceId currentDevice = deviceInfo.deviceId;
           visited.add(currentDevice);
           parentMap.put(currentDevice, deviceInfo.GetParentId());
           levelMap.put(currentDevice, deviceInfo.GetLevel());
           int identifier = AddChild(deviceInfo.GetParentId(), currentDevice);
           deviceIdentifierMap.put(currentDevice, identifier);
           IsConnectedToRoot.put(currentDevice, true);
           deviceInfo.SetLevelIdentifier(identifier);
           deviceInfo.SetDeviceAddress(GetVlaAddress(currentDevice, deviceInfo.GetLevel()));
           results.add(deviceInfo);
           for(HostId hostId : deviceIdHostIdHashMap.get(currentDevice)){
               HostInfo hostInfo = new HostInfo(hostId, currentDevice);
               hostResults.add(hostInfo);
           }
           log.info("hosts found during traversal of device id {} is {}", currentDevice, hostResults.size());
           queue.poll();

           for(DeviceId deviceId : deviceNeighbours.get(currentDevice)){
               if(deviceNeighbours.get(deviceId).contains(currentDevice)){
                  if(!visited.contains(deviceId)){
                      queue.add(new DeviceInfo(deviceId, currentDevice, deviceInfo.GetLevel() + 1));
                  }
               }
           }
       }
       return Pair.of(results, hostResults);
   }


   private Pair<ArrayList<DeviceInfo>, ArrayList<HostInfo>> UpdateLevels(DeviceId source, DeviceId dest){

        log.info("In Update Levels part source device {},  destination device {}", source, dest);
       if(IsValidLinkToAdd(source, dest)){
           DeviceId originalSource = source;
           DeviceId originalDestination = dest;
           if(IsConnectedToRoot.get(dest)){
               originalSource = dest;
               originalDestination = source;
           }
           int parentLevel = 1;
           if(!rootDeviceList.contains(originalSource)){
               parentLevel = levelMap.get(originalSource);
           }
          return DoTraversal(originalSource, originalDestination, parentLevel);
       }
       return Pair.of(new ArrayList<DeviceInfo>(), new ArrayList<HostInfo>());
   }

   private boolean IsValidLinkToAdd(DeviceId source, DeviceId destination){

           if (deviceNeighbours.get(source).contains(destination) &&
                   deviceNeighbours.get(destination).contains(source)) {
               if (IsConnectedToRoot.get(source) && IsConnectedToRoot.get(destination)) {
                   return false;
               }
               return IsConnectedToRoot.get(source) || IsConnectedToRoot.get(destination);
           }

       return false;
   }

    public Optional<RootDeviceInfo> AddDevice(DeviceId deviceId, boolean IsRootDevice){
        synchronized (this) {
            if(!deviceList.contains(deviceId)) {
                deviceList.add(deviceId);
                deviceNeighbours.put(deviceId, new ArrayList<>());
                deviceIdHostIdHashMap.put(deviceId, new ArrayList<>());
                deviceChildIdentifierCounter.put(deviceId, IDENTIFIER_START_VALUE);
                IsConnectedToRoot.put(deviceId, false);
            }
            if(IsRootDevice && !rootDeviceList.contains(deviceId)){
                int len = rootDeviceList.size();
                rootDeviceList.add(deviceId);
                IsConnectedToRoot.put(deviceId, true);
                deviceChildIdentifierCounter.put(deviceId, IDENTIFIER_START_VALUE);
                levelMap.put(deviceId, 1);
                int levelIdentifier = rootDeviceList.indexOf(deviceId) + IDENTIFIER_START_VALUE;
                //int levelIdentifier = 300;
                deviceIdentifierMap.put(deviceId, levelIdentifier);
                RootDeviceInfo rootDeviceInfo = new RootDeviceInfo(deviceId, levelIdentifier);
                rootDeviceInfo.SetVlaAddress(GetVlaAddress(deviceId, 1));
                return Optional.of(rootDeviceInfo);
            }
        }
        return Optional.empty();
    }

    public void RemoveDevice(DeviceId deviceId){
        synchronized (this) {
            if(deviceList.contains(deviceId)) {
                deviceList.remove(deviceId);
                // TODO
                //remove flow table entries related to device.
            }
        }
    }

    public ArrayList<HostInfo> AddHost(HostId hostId, DeviceId deviceId){

        ArrayList<HostInfo> results = new ArrayList<>();
        synchronized (this) {
            if (hostIdDeviceIdHashMap.containsKey(hostId)) {
                if(hostIdDeviceIdHashMap.get(hostId) == deviceId) {
                    return results;
                }
                deviceIdHostIdHashMap.get(hostIdDeviceIdHashMap.get(hostId)).remove(hostId);
                hostIdDeviceIdHashMap.remove(hostId);
                // TODO Update Table Entries
            }
            if(!deviceIdHostIdHashMap.get(deviceId).contains(hostId)) {
                hostIdDeviceIdHashMap.put(hostId, deviceId);
                deviceIdHostIdHashMap.get(deviceId).add(hostId);
                if (IsConnectedToRoot.containsKey(deviceId)) {
                    HostInfo hostInfo = new HostInfo(hostId, deviceId);
                    results.add(hostInfo);
                }
            }
        }
        return results;
    }

    public  Pair<ArrayList<DeviceInfo>, ArrayList<HostInfo>> AddLink(DeviceId source, DeviceId destination){
        synchronized (this){
            if(deviceList.contains(source) && deviceList.contains(destination)) {
                deviceNeighbours.get(source).add(destination);
                deviceNeighbours.get(destination).add(source);
                if (IsValidLinkToAdd(source, destination)) {
                    return UpdateLevels(source, destination);
                }
            }
        }
        return Pair.of(new ArrayList<>(), new ArrayList<>());
    }
}
