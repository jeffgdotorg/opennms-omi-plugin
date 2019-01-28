# opennms-omi-plugin

This plugin can be used to generate OpenNMS event definitions from OMi policy files and
provides interactive shell commands for deriving inventory and simulating SNMP traps from
NNMi logs.

This plugin requires OpenNMS Horizon 24.0.0 or greater.

# Build & install

Build and install the plugin into your local Maven repository using:
```
mvn clean install
```

From the OpenNMS Karaf shell:
```
feature:repo-add mvn:org.opennms.plugins.omi/omi-karaf-features/1.0.0-SNAPSHOT/xml
feature:install opennms-plugins-omi
bundle:watch *
```

# Events

Point the plugin to a folder on the OpenNMS system that contains the policy files (it expects these files to end in `_data`):
```
config:edit org.opennms.plugins.omi
property-set omPolicyRoot "/opt/OM_policies"
config:update
```

View the generated event definitions:
```
events:show-event-config -u "uei.opennms.org/omi"
```

# Replay

## Inventory hanlding

Replay the traps while gathering inventory information, and generate a requisition:

```
omi:replay -f /opt/OM_policies/nnmi_traps -i /tmp/import.xml
```

Add the requisition to OpenNMS:
```
curl -v -u admin:admin -X POST -H "Content-Type: application/xml" -d @/tmp/import.xml http://localhost:8980/opennms/rest/requisitions
```

Add a foreign source with no detectors:
```
curl -v -u admin:admin -X POST http://localhost:8980/opennms/rest/foreignSources \
    -H "Content-Type: application/xml" \
    --data '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><foreign-source xmlns="http://xmlns.opennms.org/xsd/config/foreign-source" name="NODES" date-stamp="2019-01-28T13:58:27.945-05:00"><scan-interval>12w</scan-interval><detectors/><policies/></foreign-source>'
```

Synchronize the import:
```
curl -v -u admin:admin -X PUT http://localhost:8980/opennms/rest/requisitions/NODES/import?rescanExisting=false
```

## Trap playback

Set the `use-address-from-varbind="true"` attribute in `etc/trapd-configuration.xml`.

```
omi:replay -f /opt/OM_policies/nnmi_traps
```
