# opennms-omi-plugin

Build and install:
```
mvn clean install
```

From the Karaf shell:
```
feature:repo-add mvn:org.opennms.plugins.omi/omi-karaf-features/1.0.0-SNAPSHOT/xml
feature:install opennms-plugins-omi
bundle:watch *
```

Run the simulate command:
```
admin@opennms> omi:simulate
Generating traps...
```
