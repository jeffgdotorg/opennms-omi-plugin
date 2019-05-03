/*******************************************************************************
 * This file is part of OpenNMS(R).
 *
 * Copyright (C) 2019 The OpenNMS Group, Inc.
 * OpenNMS(R) is Copyright (C) 1999-2019 The OpenNMS Group, Inc.
 *
 * OpenNMS(R) is a registered trademark of The OpenNMS Group, Inc.
 *
 * OpenNMS(R) is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 *
 * OpenNMS(R) is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with OpenNMS(R).  If not, see:
 *      http://www.gnu.org/licenses/
 *
 * For more information contact:
 *     OpenNMS(R) Licensing <license@opennms.org>
 *     http://www.opennms.org/
 *     http://www.opennms.com/
 *******************************************************************************/

package org.opennms.plugins.omi;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.opennms.plugins.omi.OmiEventConfExtension.UEI_PREFIX;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import org.jline.utils.Log;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.opennms.integration.api.v1.config.events.AlarmData;
import org.opennms.integration.api.v1.config.events.AlarmType;
import org.opennms.integration.api.v1.config.events.EventDefinition;
import org.opennms.integration.api.v1.config.events.LogMessage;
import org.opennms.integration.api.v1.config.events.LogMsgDestType;
import org.opennms.integration.api.v1.config.events.Mask;
import org.opennms.integration.api.v1.config.events.Parameter;
import org.opennms.integration.api.v1.config.events.Varbind;
import org.opennms.integration.api.v1.model.Severity;

import com.google.common.io.Resources;

public class OmiEventConfExtensionTest {

    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    @Test
    public void canReplacePlaceholderTokens() {
        assertThat(OmiEventConfExtension.replacePolicyvarPlaceholderTokens("<$1>"), equalTo("%parm[#1]%"));
        assertThat(OmiEventConfExtension.replacePolicyvarPlaceholderTokens("<$2>"), equalTo("%parm[#2]%"));
        assertThat(OmiEventConfExtension.replacePolicyvarPlaceholderTokens("<$1>-<$2>"), equalTo("%parm[#1]%-%parm[#2]%"));
    }

    @Test
    public void canExtractPlaceholderTokens() {
        assertThat(OmiEventConfExtension.extractPlaceholderTokens("<$1>"), equalTo(Arrays.asList("%parm[#1]%")));
        assertThat(OmiEventConfExtension.extractPlaceholderTokens("<$2>"), equalTo(Arrays.asList("%parm[#2]%")));
        assertThat(OmiEventConfExtension.extractPlaceholderTokens("<$1>-<$2>"), equalTo(Arrays.asList("%parm[#1]%", "%parm[#2]%")));
    }
    
    @Test
    public void canDecorateEmailAddresses() {
        String helpText = "EVENT NAME: eventTrap_21008\n" + 
                "\n" + 
                "EVENT TYPE: EMC Avamar Backup SNMP trap\n" + 
                "\n" + 
                "DESCRIPTION:\n" + 
                "Avamar Event CODE : 21008\n" + 
                "SUMMARY : VERSION MISMATCH.\n" + 
                "CATEGORY : SYSTEM\n" + 
                "TYPE : ERROR\n" + 
                "SEVERITY : 2:PROCESS\n" + 
                "DESCRIPTION : THE ADMINISTRATOR CLIENT VERSION DOES NOT MATCH THE ADMINISTRATOR SERVER.\n" + 
                "FOR WHOM : ALL USERS\n" + 
                "NOTES :\n" + 
                "\n" + 
                "RECOMMENDED ACTION: RUN A VERSION OF THE CLIENT THAT MATCHES A VERSION OF THE SERVER.\n" + 
                "\n" + 
                "NOTIFICATION: Alert_Storage@uspto.gov,ETBS_Admin@uspto.gov\n" + 
                "\n" + 
                "COMMENTS:\n" + 
                "\n" + 
                "WEB LINKS: http://www.emc.com/support-training/index.htm\n" + 
                "\n" + 
                "GATHER SCRIPTS:\n" + 
                "\n";
        
        String expected = "EVENT NAME: eventTrap_21008\n" + 
                "\n" + 
                "EVENT TYPE: EMC Avamar Backup SNMP trap\n" + 
                "\n" + 
                "DESCRIPTION:\n" + 
                "Avamar Event CODE : 21008\n" + 
                "SUMMARY : VERSION MISMATCH.\n" + 
                "CATEGORY : SYSTEM\n" + 
                "TYPE : ERROR\n" + 
                "SEVERITY : 2:PROCESS\n" + 
                "DESCRIPTION : THE ADMINISTRATOR CLIENT VERSION DOES NOT MATCH THE ADMINISTRATOR SERVER.\n" + 
                "FOR WHOM : ALL USERS\n" + 
                "NOTES :\n" + 
                "\n" + 
                "RECOMMENDED ACTION: RUN A VERSION OF THE CLIENT THAT MATCHES A VERSION OF THE SERVER.\n" + 
                "\n" + 
                "NOTIFICATION: <a href=\"mailto:Alert_Storage@uspto.gov\">Alert_Storage@uspto.gov</a>,<a href=\"mailto:ETBS_Admin@uspto.gov\">ETBS_Admin@uspto.gov</a>\n" + 
                "\n" + 
                "COMMENTS:\n" + 
                "\n" + 
                "WEB LINKS: http://www.emc.com/support-training/index.htm\n" + 
                "\n" + 
                "GATHER SCRIPTS:\n" + 
                "\n";
        
        assertThat(OmiEventConfExtension.decorateEmailAddresses(helpText), equalTo(expected));
    }
    
    @Test
    public void canDecorateHttpLinks() {
        String helpText = "EVENT NAME: eventTrap_21008\n" + 
                "\n" + 
                "EVENT TYPE: EMC Avamar Backup SNMP trap\n" + 
                "\n" + 
                "DESCRIPTION:\n" + 
                "Avamar Event CODE : 21008\n" + 
                "SUMMARY : VERSION MISMATCH.\n" + 
                "CATEGORY : SYSTEM\n" + 
                "TYPE : ERROR\n" + 
                "SEVERITY : 2:PROCESS\n" + 
                "DESCRIPTION : THE ADMINISTRATOR CLIENT VERSION DOES NOT MATCH THE ADMINISTRATOR SERVER.\n" + 
                "FOR WHOM : ALL USERS\n" + 
                "NOTES :\n" + 
                "\n" + 
                "RECOMMENDED ACTION: RUN A VERSION OF THE CLIENT THAT MATCHES A VERSION OF THE SERVER.\n" + 
                "\n" + 
                "NOTIFICATION: Alert_Storage@uspto.gov,ETBS_Admin@uspto.gov\n" + 
                "\n" + 
                "COMMENTS:\n" + 
                "\n" + 
                "WEB LINKS: http://www.emc.com/support-training/index.htm\n" + 
                "\n" + 
                "GATHER SCRIPTS:\n" + 
                "\n";
        
        String expected = "EVENT NAME: eventTrap_21008\n" + 
                "\n" + 
                "EVENT TYPE: EMC Avamar Backup SNMP trap\n" + 
                "\n" + 
                "DESCRIPTION:\n" + 
                "Avamar Event CODE : 21008\n" + 
                "SUMMARY : VERSION MISMATCH.\n" + 
                "CATEGORY : SYSTEM\n" + 
                "TYPE : ERROR\n" + 
                "SEVERITY : 2:PROCESS\n" + 
                "DESCRIPTION : THE ADMINISTRATOR CLIENT VERSION DOES NOT MATCH THE ADMINISTRATOR SERVER.\n" + 
                "FOR WHOM : ALL USERS\n" + 
                "NOTES :\n" + 
                "\n" + 
                "RECOMMENDED ACTION: RUN A VERSION OF THE CLIENT THAT MATCHES A VERSION OF THE SERVER.\n" + 
                "\n" + 
                "NOTIFICATION: Alert_Storage@uspto.gov,ETBS_Admin@uspto.gov\n" + 
                "\n" + 
                "COMMENTS:\n" + 
                "\n" + 
                "WEB LINKS: <a target=\"_blank\" href=\"http://www.emc.com/support-training/index.htm\">http://www.emc.com/support-training/index.htm</a>\n" + 
                "\n" + 
                "GATHER SCRIPTS:\n" + 
                "\n";
        assertThat(OmiEventConfExtension.decorateHttpLinks(helpText), equalTo(expected));
    }
    
    @Test
    public void canDecorateWholeOperInstruct() {
        String helpText = "EVENT NAME: eventTrap_21008\n" + 
                "\n" + 
                "EVENT TYPE: EMC Avamar Backup SNMP trap\n" + 
                "\n" + 
                "DESCRIPTION:\n" + 
                "Avamar Event CODE : 21008\n" + 
                "SUMMARY : VERSION MISMATCH.\n" + 
                "CATEGORY : SYSTEM\n" + 
                "TYPE : ERROR\n" + 
                "SEVERITY : 2:PROCESS\n" + 
                "DESCRIPTION : THE ADMINISTRATOR CLIENT VERSION DOES NOT MATCH THE ADMINISTRATOR SERVER.\n" + 
                "FOR WHOM : ALL USERS\n" + 
                "NOTES :\n" + 
                "\n" + 
                "RECOMMENDED ACTION: RUN A VERSION OF THE CLIENT THAT MATCHES A VERSION OF THE SERVER.\n" + 
                "\n" + 
                "NOTIFICATION: Alert_Storage@uspto.gov,ETBS_Admin@uspto.gov\n" + 
                "\n" + 
                "COMMENTS:\n" + 
                "\n" + 
                "WEB LINKS: http://www.emc.com/support-training/index.htm\n" + 
                "\n" + 
                "GATHER SCRIPTS:\n" + 
                "\n" + 
                "MORE WEB LINKS: https://www.emc.com/stuff/and/such.blah";
        
        String expected = "<pre>EVENT NAME: eventTrap_21008\n" + 
                "\n" + 
                "EVENT TYPE: EMC Avamar Backup SNMP trap\n" + 
                "\n" + 
                "DESCRIPTION:\n" + 
                "Avamar Event CODE : 21008\n" + 
                "SUMMARY : VERSION MISMATCH.\n" + 
                "CATEGORY : SYSTEM\n" + 
                "TYPE : ERROR\n" + 
                "SEVERITY : 2:PROCESS\n" + 
                "DESCRIPTION : THE ADMINISTRATOR CLIENT VERSION DOES NOT MATCH THE ADMINISTRATOR SERVER.\n" + 
                "FOR WHOM : ALL USERS\n" + 
                "NOTES :\n" + 
                "\n" + 
                "RECOMMENDED ACTION: RUN A VERSION OF THE CLIENT THAT MATCHES A VERSION OF THE SERVER.\n" + 
                "\n" + 
                "NOTIFICATION: <a href=\"mailto:Alert_Storage@uspto.gov\">Alert_Storage@uspto.gov</a>,<a href=\"mailto:ETBS_Admin@uspto.gov\">ETBS_Admin@uspto.gov</a>\n" + 
                "\n" + 
                "COMMENTS:\n" + 
                "\n" + 
                "WEB LINKS: <a target=\"_blank\" href=\"http://www.emc.com/support-training/index.htm\">http://www.emc.com/support-training/index.htm</a>\n" + 
                "\n" + 
                "GATHER SCRIPTS:\n" + 
                "\n" +
                "MORE WEB LINKS: <a target=\"_blank\" href=\"https://www.emc.com/stuff/and/such.blah\">https://www.emc.com/stuff/and/such.blah</a></pre>";
        
        assertThat(OmiEventConfExtension.decorateOperInstruct(helpText), equalTo(expected));
    }

    @Test
    public void canProvideBasicNetappDefinitions() throws IOException {
        final File policyData = temporaryFolder.newFile("netapp_test_policy_data");
        try (InputStream is = Resources.getResource("netapp_test_policy_data").openStream()) {
            Files.copy(is, policyData.toPath(), StandardCopyOption.REPLACE_EXISTING);
        }

        OmiDefinitionProvider omiDefProvider = new DefaultOmiDefinitionProvider(temporaryFolder.getRoot(), "");
        OmiEventConfExtension omiEventConfExtension = new OmiEventConfExtension(omiDefProvider);

        final List<EventDefinition> eventDefs = omiEventConfExtension.getEventDefinitions();

        // Make sure we have at least 1
        assertThat(eventDefs, hasSize(greaterThanOrEqualTo(1)));

        // Look for a specific entry
        EventDefinition eventDef = findEvent(eventDefs, UEI_PREFIX + "NetApp_Link_Up");
        assertThat(eventDef, notNullValue());
        assertThat(eventDef.getPriority(), equalTo(1000));
        assertThat(eventDef.getLabel(), equalTo("NetApp_Link_Up"));
        assertThat(eventDef.getSeverity(), equalTo(Severity.NORMAL));

        // Validate the log message
        LogMessage logMessage = eventDef.getLogMessage();
        assertThat(logMessage, notNullValue());
        
        assertThat(logMessage.getContent(), equalTo("Link %parm[#1]% up."));
        assertThat(logMessage.getDestination(), equalTo(LogMsgDestType.LOGNDISPLAY));

        // Validate the alarm
        AlarmData alarmData = eventDef.getAlarmData();
        assertThat(alarmData, notNullValue());
        // Don't know how to match problems to clears, so everything is a type 3
        assertThat(alarmData.getType(), equalTo(AlarmType.PROBLEM_WITHOUT_RESOLUTION));
        // The reduction key should include all parameters referenced from the label
        assertThat(alarmData.getReductionKey(), equalTo("%uei%:%dpname%:%nodeid%:%parm[#1]%"));

        // Validate that the APPLICATION and MSGGRP tokens got transformed into event parameters
        List<Parameter> parameters = eventDef.getParameters();
        assertThat(parameters, hasSize(equalTo(2)));
        Parameter applicationParameter = findParameter(parameters, "Application");
        assertThat(applicationParameter.getValue(), equalTo("NetApp"));
        Parameter msgGrpParameter = findParameter(parameters, "MsgGrp");
        assertThat(msgGrpParameter.getValue(), equalTo("Storage"));
        
        // Look for another specific entry
        eventDef = findEvent(eventDefs, UEI_PREFIX + "NetApp_Link_Down");
        assertThat(eventDef, notNullValue());
        assertThat(eventDef.getPriority(), equalTo(1000));
        assertThat(eventDef.getLabel(), equalTo("NetApp_Link_Down"));
        assertThat(eventDef.getSeverity(), equalTo(Severity.MAJOR));

        // Validate the log message
        logMessage = eventDef.getLogMessage();
        assertThat(logMessage, notNullValue());
        assertThat(logMessage.getContent(), equalTo("Link %parm[#1]% down."));
        assertThat(logMessage.getDestination(), equalTo(LogMsgDestType.LOGNDISPLAY));

        // Validate the alarm
        alarmData = eventDef.getAlarmData();
        assertThat(alarmData, notNullValue());
        // Don't know how to match problems to clears, so everything is a type 3
        assertThat(alarmData.getType(), equalTo(AlarmType.PROBLEM_WITHOUT_RESOLUTION));
        // The reduction key should include all parameters referenced from the label
        assertThat(alarmData.getReductionKey(), equalTo("%uei%:%dpname%:%nodeid%:%parm[#1]%"));

        // Validate that the APPLICATION and MSGGRP tokens got transformed into event parameters
        parameters = eventDef.getParameters();
        assertThat(parameters, hasSize(equalTo(2)));
        applicationParameter = findParameter(parameters, "Application");
        assertThat(applicationParameter.getValue(), equalTo("NetApp"));
        msgGrpParameter = findParameter(parameters, "MsgGrp");
        assertThat(msgGrpParameter.getValue(), equalTo("Storage"));
    }

    @Test
    public void canProvideModerateTandbergDefinitions() throws IOException {
        final File policyData = temporaryFolder.newFile("tandberg_test_policy_data");
        try (InputStream is = Resources.getResource("tandberg_test_policy_data").openStream()) {
            Files.copy(is, policyData.toPath(), StandardCopyOption.REPLACE_EXISTING);
        }

        OmiDefinitionProvider omiDefProvider = new DefaultOmiDefinitionProvider(temporaryFolder.getRoot(), "");
        OmiEventConfExtension omiEventConfExtension = new OmiEventConfExtension(omiDefProvider);

        final List<EventDefinition> eventDefs = omiEventConfExtension.getEventDefinitions();

        // Make sure we have at least 26
        assertThat(eventDefs, hasSize(greaterThanOrEqualTo(26)));

        // Look for a specific entry
        EventDefinition eventDef = findEvent(eventDefs, UEI_PREFIX + "coldStart_Tandberg");
        assertThat(eventDef, notNullValue());
        assertThat(eventDef.getPriority(), equalTo(1000));
        assertThat(eventDef.getLabel(), equalTo("coldStart_Tandberg"));
        assertThat(eventDef.getSeverity(), equalTo(Severity.MINOR));

        // Validate the log message
        LogMessage logMessage = eventDef.getLogMessage();
        assertThat(logMessage, notNullValue());
        
        assertThat(logMessage.getContent(), equalTo("Agent Up with Possible Changes (coldStart Trap)"));
        assertThat(logMessage.getDestination(), equalTo(LogMsgDestType.LOGONLY));

        // Validate the alarm
        AlarmData alarmData = eventDef.getAlarmData();
        assertThat(alarmData, notNullValue());
        // Don't know how to match problems to clears, so everything is a type 3
        assertThat(alarmData.getType(), equalTo(AlarmType.PROBLEM_WITHOUT_RESOLUTION));
        // The reduction key should include all parameters referenced from the label (none, in this case)
        assertThat(alarmData.getReductionKey(), equalTo("%uei%:%dpname%:%nodeid%"));
        
        // Validate that the APPLICATION and MSGGRP tokens got transformed into event parameters
        List<Parameter> parameters = eventDef.getParameters();
        assertThat(parameters, hasSize(equalTo(2)));
        Parameter applicationParameter = findParameter(parameters, "Application");
        assertThat(applicationParameter.getValue(), equalTo("TandBerg"));
        Parameter msgGrpParameter = findParameter(parameters, "MsgGrp");
        assertThat(msgGrpParameter.getValue(), equalTo("Video"));
        
        // Look for another specific entry
        eventDef = findEvent(eventDefs, UEI_PREFIX + "tmsTrapLostOrGotResponse_Lost");
        assertThat(eventDef, notNullValue());
        assertThat(eventDef.getPriority(), equalTo(1000));
        assertThat(eventDef.getLabel(), equalTo("tmsTrapLostOrGotResponse_Lost"));
        assertThat(eventDef.getSeverity(), equalTo(Severity.MINOR));

        // Validate the mask
        Mask eventMask = eventDef.getMask();
        List<Varbind> maskVarbinds = eventMask.getVarbinds();
        assertThat(maskVarbinds.size(), equalTo(1));
        assertThat(maskVarbinds.get(0).getNumber(), equalTo(7));
        assertThat(maskVarbinds.get(0).getValues().size(), equalTo(1));
        assertThat(maskVarbinds.get(0).getValues().get(0), equalTo("0"));
        
        // Validate the log message
        logMessage = eventDef.getLogMessage();
        assertThat(logMessage, notNullValue());
        assertThat(logMessage.getContent(), equalTo("TMS has lost connection with system. System name in TMS: \"%parm[#9]%\". MAC address: \"%parm[#8]%\". Event type value: \"%parm[#4]%\"."));
        assertThat(logMessage.getDestination(), equalTo(LogMsgDestType.LOGNDISPLAY));

        // Validate the alarm
        alarmData = eventDef.getAlarmData();
        assertThat(alarmData, notNullValue());
        // Don't know how to match problems to clears, so everything is a type 3
        assertThat(alarmData.getType(), equalTo(AlarmType.PROBLEM_WITHOUT_RESOLUTION));
        // The reduction key should include all parameters referenced from the label
        assertThat(alarmData.getReductionKey(), equalTo("%uei%:%dpname%:%nodeid%:%parm[#9]%:%parm[#8]%:%parm[#4]%"));

        // Validate that the APPLICATION and MSGGRP tokens got transformed into event parameters
        parameters = eventDef.getParameters();
        assertThat(parameters, hasSize(equalTo(2)));
        applicationParameter = findParameter(parameters, "Application");
        assertThat(applicationParameter.getValue(), equalTo("TandBerg"));
        msgGrpParameter = findParameter(parameters, "MsgGrp");
        assertThat(msgGrpParameter.getValue(), equalTo("Video"));
        
        // Look for the bottom catch-all entry, and validate that <$*> translated correctly
        eventDef = findEvent(eventDefs, UEI_PREFIX + "TandBerg_Generic_Event");
        assertThat(eventDef, notNullValue());
        assertThat(eventDef.getPriority(), equalTo(1000));
        assertThat(eventDef.getLabel(), equalTo("TandBerg_Generic_Event"));
        
        // Validate the logmsg.dest
        logMessage = eventDef.getLogMessage();
        assertThat(logMessage, notNullValue());
        assertThat(logMessage.getContent(), equalTo("%parm[all]%"));
        assertThat(logMessage.getDestination(), equalTo(LogMsgDestType.LOGONLY));
    }
    
    @Test
    public void canProvideVoluminousAvamarDefinitions() throws IOException {
        final File policyData = temporaryFolder.newFile("avamar_test_policy_data");
        try (InputStream is = Resources.getResource("avamar_test_policy_data").openStream()) {
            Files.copy(is, policyData.toPath(), StandardCopyOption.REPLACE_EXISTING);
        }

        OmiDefinitionProvider omiDefProvider = new DefaultOmiDefinitionProvider(temporaryFolder.getRoot(), "");
        OmiEventConfExtension omiEventConfExtension = new OmiEventConfExtension(omiDefProvider);

        final List<EventDefinition> eventDefs = omiEventConfExtension.getEventDefinitions();

        // Make sure we have the right number
        assertThat(eventDefs, hasSize(greaterThanOrEqualTo(4606)));

        // Look for a specific entry
        EventDefinition eventDef = findEvent(eventDefs, UEI_PREFIX + "burmActivityTrap");
        assertThat(eventDef, notNullValue());
        assertThat(eventDef.getPriority(), equalTo(1000));
        assertThat(eventDef.getLabel(), equalTo("burmActivityTrap"));
        assertThat(eventDef.getSeverity(), equalTo(Severity.INDETERMINATE));

        // Validate the log message
        LogMessage logMessage = eventDef.getLogMessage();
        assertThat(logMessage, notNullValue());
        
        assertThat(logMessage.getContent(), equalTo("burmActivityTrap"));
        assertThat(logMessage.getDestination(), equalTo(LogMsgDestType.DISCARDTRAPS));

        // Validate the alarm
        AlarmData alarmData = eventDef.getAlarmData();
        assertThat(alarmData, notNullValue());
        // Don't know how to match problems to clears, so everything is a type 3
        assertThat(alarmData.getType(), equalTo(AlarmType.PROBLEM_WITHOUT_RESOLUTION));
        // The reduction key should include all parameters referenced from the label (none, in this case)
        assertThat(alarmData.getReductionKey(), equalTo("%uei%:%dpname%:%nodeid%"));
        
        // Validate that the APPLICATION and MSGGRP tokens got transformed into event parameters
        List<Parameter> parameters = eventDef.getParameters();
        assertThat(parameters, hasSize(equalTo(2)));
        Parameter applicationParameter = findParameter(parameters, "Application");
        assertThat(applicationParameter.getValue(), equalTo("Avamar"));
        Parameter msgGrpParameter = findParameter(parameters, "MsgGrp");
        assertThat(msgGrpParameter.getValue(), equalTo("Backup"));
    }
    
    @Test
    public void canProvideNetIQDefinitions() throws IOException {
        final File policyData = temporaryFolder.newFile("netiq_test_policy_data");
        try (InputStream is = Resources.getResource("netiq_test_policy_data").openStream()) {
            Files.copy(is, policyData.toPath(), StandardCopyOption.REPLACE_EXISTING);
        }

        OmiDefinitionProvider omiDefProvider = new DefaultOmiDefinitionProvider(temporaryFolder.getRoot(), "");
        OmiEventConfExtension omiEventConfExtension = new OmiEventConfExtension(omiDefProvider);

        final List<EventDefinition> eventDefs = omiEventConfExtension.getEventDefinitions();

        // Make sure we have the right number
        assertThat(eventDefs, hasSize(equalTo(78)));

        // Look for a specific entry
        EventDefinition eventDef = findEvent(eventDefs, UEI_PREFIX + "NetIQWarning_Cisco");
        assertThat(eventDef, notNullValue());
        assertThat(eventDef.getPriority(), equalTo(1000));
        assertThat(eventDef.getLabel(), equalTo("NetIQWarning_Cisco"));
        assertThat(eventDef.getSeverity(), equalTo(Severity.WARNING));

        // Validate the log message
        LogMessage logMessage = eventDef.getLogMessage();
        assertThat(logMessage, notNullValue());
        
        assertThat(logMessage.getContent(), equalTo("%parm[#5]%: %parm[#7]% - %parm[#8]%"));
//        assertThat(logMessage.getDestination(), equalTo(LogMsgDestType.LOGONLY));

        // Validate the alarm
        AlarmData alarmData = eventDef.getAlarmData();
        assertThat(alarmData, notNullValue());
        // Don't know how to match problems to clears, so everything is a type 3
        assertThat(alarmData.getType(), equalTo(AlarmType.PROBLEM_WITHOUT_RESOLUTION));
        // The reduction key should include all parameters referenced from the label (none, in this case)
        assertThat(alarmData.getReductionKey(), equalTo("%uei%:%dpname%:%nodeid%:%parm[#5]%:%parm[#7]%:%parm[#8]%"));
        
        // Validate that the APPLICATION and MSGGRP tokens got transformed into event parameters
        List<Parameter> parameters = eventDef.getParameters();
        assertThat(parameters, hasSize(equalTo(2)));
        Parameter applicationParameter = findParameter(parameters, "Application");
        assertThat(applicationParameter.getValue(), equalTo("%parm[#9]%"));
        assertThat(applicationParameter.shouldExpand(), equalTo(true));
        Parameter msgGrpParameter = findParameter(parameters, "MsgGrp");
        assertThat(msgGrpParameter.getValue(), equalTo("PBXDiag"));
    }
    
    @Test
    public void canProvideTeamQuestDefinitions() throws IOException {
        final File policyData = temporaryFolder.newFile("teamquest_test_policy_data");
        try (InputStream is = Resources.getResource("teamquest_test_policy_data").openStream()) {
            Files.copy(is, policyData.toPath(), StandardCopyOption.REPLACE_EXISTING);
        }

        OmiDefinitionProvider omiDefProvider = new DefaultOmiDefinitionProvider(temporaryFolder.getRoot(), "");
        OmiEventConfExtension omiEventConfExtension = new OmiEventConfExtension(omiDefProvider);

        final List<EventDefinition> eventDefs = omiEventConfExtension.getEventDefinitions();

        // Make sure we have the right number
        assertThat(eventDefs, hasSize(equalTo(104)));

        // Look for a specific entry
        EventDefinition eventDef = findEvent(eventDefs, UEI_PREFIX + "TeamQuest_Event_Test");
        assertThat(eventDef, notNullValue());
        assertThat(eventDef.getPriority(), equalTo(1000));
        assertThat(eventDef.getLabel(), equalTo("TeamQuest_Event_Test"));
        assertThat(eventDef.getSeverity(), equalTo(Severity.MINOR));

        // Validate the log message
        LogMessage logMessage = eventDef.getLogMessage();
        assertThat(logMessage, notNullValue());
        
        assertThat(logMessage.getContent(), equalTo("%parm[#1]%"));
        assertThat(logMessage.getDestination(), equalTo(LogMsgDestType.LOGNDISPLAY));

        // Validate the alarm
        AlarmData alarmData = eventDef.getAlarmData();
        assertThat(alarmData, notNullValue());
        // Don't know how to match problems to clears, so everything is a type 3
        assertThat(alarmData.getType(), equalTo(AlarmType.PROBLEM_WITHOUT_RESOLUTION));
        // The reduction key should include all parameters referenced from the label (none, in this case)
        assertThat(alarmData.getReductionKey(), equalTo("%uei%:%dpname%:%nodeid%:%parm[#1]%"));
        
        // Validate that the APPLICATION and MSGGRP tokens got transformed into event parameters
        List<Parameter> parameters = eventDef.getParameters();
        assertThat(parameters, hasSize(equalTo(2)));
        Parameter applicationParameter = findParameter(parameters, "Application");
        assertThat(applicationParameter.getValue(), equalTo("TeamQuest"));
        assertThat(applicationParameter.shouldExpand(), equalTo(false));
        Parameter msgGrpParameter = findParameter(parameters, "MsgGrp");
        assertThat(msgGrpParameter.getValue(), equalTo("Performance_SPB"));
        
        // Look for a second event, and validate user variable substitution in its logmsg
        eventDef = findEvent(eventDefs, UEI_PREFIX + "TeamQuest_Event_Critical_High_Disk_Response");
        assertThat(eventDef, notNullValue());
        assertThat(eventDef.getPriority(), equalTo(1000));
        assertThat(eventDef.getLabel(), equalTo("TeamQuest_Event_Critical_High_Disk_Response"));
        assertThat(eventDef.getSeverity(), equalTo(Severity.CRITICAL));
        
        Mask mask = eventDef.getMask();
        assertThat(mask, notNullValue());
        assertThat(mask.getVarbinds().size(), equalTo(1));
        Varbind vb = mask.getVarbinds().get(0);
        assertThat(vb, notNullValue());
        assertThat(vb.getNumber(), equalTo(1));
        assertThat(vb.getValues().size(), equalTo(1));
        assertThat(vb.getValues().get(0), equalTo("~^(?<server>\\w+?) - Critical:High_Disk_Response \\w+? (?<message>.*?) at.*"));
        
        // Validate the log message
        logMessage = eventDef.getLogMessage();
        assertThat(logMessage.getContent(), equalTo("Critical:High_Disk_Response %parm[message]%"));
        assertThat(logMessage.getDestination(), equalTo(LogMsgDestType.LOGNDISPLAY));
    }
    
    @Test
    public void canSetPriorityOnCatchAllEvents() throws IOException {
        final File policyData = temporaryFolder.newFile("netapp_test_policy_data");
        try (InputStream is = Resources.getResource("netapp_test_policy_data").openStream()) {
            Files.copy(is, policyData.toPath(), StandardCopyOption.REPLACE_EXISTING);
        }

        OmiDefinitionProvider omiDefProvider = new DefaultOmiDefinitionProvider(temporaryFolder.getRoot(), "xxx, netapp_test_policy_data");
        OmiEventConfExtension omiEventConfExtension = new OmiEventConfExtension(omiDefProvider);

        final List<EventDefinition> eventDefs = omiEventConfExtension.getEventDefinitions();

        // Make sure we have at least 1
        assertThat(eventDefs, hasSize(greaterThanOrEqualTo(1)));

        // Look for a specific entry
        EventDefinition eventDef = findEvent(eventDefs, UEI_PREFIX + "NetApp_Link_Up");
        assertThat(eventDef, notNullValue());
        assertThat(eventDef.getPriority(), equalTo(999));
        
        // Look for another specific entry
        eventDef = findEvent(eventDefs, UEI_PREFIX + "NetApp_Link_Down");
        assertThat(eventDef, notNullValue());
        assertThat(eventDef.getPriority(), equalTo(999));
    }
    
    @Test
    public void canReplaceSimpleActionGroups() throws IOException {
        String omiPattern = "^fa-<*>a.<*>example.gov$";
        assertThat(OmiEventConfExtension.translateOmiPatternToRegex(omiPattern), equalTo("^fa-.*?a..*?example.gov$"));
    }
    
    @Test
    public void canReplaceComplexActionGroups() throws Exception {
        String omiPattern = "";
        
        // Start with a gimme
        omiPattern = "opener <4*.stuff> closer";
        assertThat(OmiEventConfExtension.translateOmiPatternToRegex(omiPattern), equalTo(".*opener (?<stuff>.{4}) closer.*"));

        // Now try it with multiple action groups
        omiPattern = "Did <4*.stuff> with <8@.thing> and <16#.tertiary> while <32_> yes I did";
        assertThat(OmiEventConfExtension.translateOmiPatternToRegex(omiPattern),
                   equalTo(".*Did (?<stuff>.{4}) with (?<thing>\\w{8}) and (?<tertiary>\\d{16}) while " + OmiEventConfExtension.TOKEN_UNDERSCORE_REGEX_EQUIVALENT + "{32} yes I did.*"));
        
        // This one challenged me late in development
        omiPattern = "I need a <[foo|bar].thing>, please";
        assertThat(OmiEventConfExtension.translateOmiPatternToRegex(omiPattern),
                   equalTo(".*I need a (?<thing>(foo|bar)), please.*"));
        
        // Now a difficult, real-life example
        omiPattern = "Major:CPU_Busy_Alarm <1*><@.cpu>,<@.workload><1*> due to cpu_busy_alias<*.cpu_busy>,proc_queuelength_alias<*.proc_queue>,<*>workload_cpu_alias<*.workload_cpu>";
        assertThat(OmiEventConfExtension.translateOmiPatternToRegex(omiPattern),
                   equalTo(".*Major:CPU_Busy_Alarm .{1}(?<cpu>\\w+?),(?<workload>\\w+?).{1} due to cpu_busy_alias(?<cpuBusy>.*?),proc_queuelength_alias(?<procQueue>.*?),.*?workload_cpu_alias(?<workloadCpu>.*?).*"));
    
        // And another real-life one
        omiPattern = "^/<*>/[<*.source>%<@>|<*.source>]$";
        assertThat(OmiEventConfExtension.translateOmiPatternToRegex(omiPattern),
                   equalTo("^/.*?/((?<source>.*?)%\\w+?|(?<source>.*?))$"));
    }
    
    @Test
    public void canReplaceSquareGroups() throws Exception {
        // Easy one first
        String omiPattern = "This [foo|bar] is whatever";
        assertThat(OmiEventConfExtension.translateOmiPatternToRegex(omiPattern),
                   equalTo(".*This (foo|bar) is whatever.*"));
        
        // Now a nested few
        omiPattern = "Th[is one|ese[two|three|many]] [is|are] a number";
        assertThat(OmiEventConfExtension.translateOmiPatternToRegex(omiPattern),
                   equalTo(".*Th(is one|ese(two|three|many)) (is|are) a number.*"));
    }
    
    @Test
    public void canReplaceMixedBags() throws Exception {
        String omiPattern = "^<[<*>Common/rbac<*>].message>$";
        assertThat(OmiEventConfExtension.translateOmiPatternToRegex(omiPattern),
                   equalTo("^(?<message>(.*?Common/rbac.*?))$"));
    }
    
    @Test
    public void canAdaptVarNamesToRegex() throws Exception {
        String omiVar = "host_name";
        assertThat(OmiEventConfExtension.adaptUserVarNameToRegex(omiVar), equalTo("hostName"));
        
        omiVar = "host_name-too";
        assertThat(OmiEventConfExtension.adaptUserVarNameToRegex(omiVar), equalTo("hostNameToo"));
        
        omiVar = "message";
        assertThat(OmiEventConfExtension.adaptUserVarNameToRegex(omiVar), equalTo("message"));
    }
    
    private static EventDefinition findEvent(List<EventDefinition> eventDefs, String uei) {
        return eventDefs.stream().filter(e -> Objects.equals(e.getUei(), uei)).findAny().orElse(null);
    }

    private static Parameter findParameter(List<Parameter> parameters, String name) {
        return parameters.stream().filter(p -> Objects.equals(p.getName(), name)).findAny().orElse(null);
    }
}
