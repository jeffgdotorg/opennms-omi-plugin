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

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.opennms.integration.api.v1.config.events.AlarmData;
import org.opennms.integration.api.v1.config.events.AlarmType;
import org.opennms.integration.api.v1.config.events.EventDefinition;
import org.opennms.integration.api.v1.config.events.LogMessage;
import org.opennms.integration.api.v1.config.events.LogMsgDestType;
import org.opennms.integration.api.v1.model.Severity;

import com.google.common.io.Resources;

public class OmiEventConfExtensionTest {

    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    @Test
    public void canReplacePlaceholderTokens() {
        assertThat(OmiEventConfExtension.replacePlaceholderTokens("<$1>"), equalTo("%parm[#1]%"));
        assertThat(OmiEventConfExtension.replacePlaceholderTokens("<$2>"), equalTo("%parm[#2]%"));
        assertThat(OmiEventConfExtension.replacePlaceholderTokens("<$1>-<$2>"), equalTo("%parm[#1]%-%parm[#2]%"));
    }

    @Test
    public void canExtractPlaceholderTokens() {
        assertThat(OmiEventConfExtension.extractPlaceholderTokens("<$1>"), equalTo(Arrays.asList("%parm[#1]%")));
        assertThat(OmiEventConfExtension.extractPlaceholderTokens("<$2>"), equalTo(Arrays.asList("%parm[#2]%")));
        assertThat(OmiEventConfExtension.extractPlaceholderTokens("<$1>-<$2>"), equalTo(Arrays.asList("%parm[#1]%", "%parm[#2]%")));
    }

    @Test
    public void canProvideDefinitions() throws IOException {
        final File policyData = temporaryFolder.newFile("policy_data");
        try (InputStream is = Resources.getResource("policy_data").openStream()) {
            Files.copy(is, policyData.toPath(), StandardCopyOption.REPLACE_EXISTING);
        }

        OmiDefinitionProvider omiDefProvider = new DefaultOmiDefinitionProvider(temporaryFolder.getRoot());
        OmiEventConfExtension omiEventConfExtension = new OmiEventConfExtension(omiDefProvider);

        final List<EventDefinition> eventDefs = omiEventConfExtension.getEventDefinitions();

        // Make sure we have at least 1
        assertThat(eventDefs, hasSize(greaterThanOrEqualTo(1)));

        // Look for a specific entry
        EventDefinition eventDef = findEvent(eventDefs, UEI_PREFIX + "NetApp_Link_Up");
        assertThat(eventDef, notNullValue());
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

        // Look for another specific entry
        eventDef = findEvent(eventDefs, UEI_PREFIX + "NetApp_Link_Down");
        assertThat(eventDef, notNullValue());
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
    }

    private static EventDefinition findEvent(List<EventDefinition> eventDefs, String uei) {
        return eventDefs.stream().filter(e -> Objects.equals(e.getUei(), uei)).findAny().orElse(null);
    }
}
