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

package org.opennms.plugins.nnmi;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.LinkedList;
import java.util.List;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.opennms.integration.api.v1.model.InMemoryEvent;
import org.snmp4j.PDU;

import com.google.common.io.Resources;

public class TrapLogReplayerTest {

    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    @Test
    public void canReplayTrapLog() throws IOException {
        final File nnmiTraps = temporaryFolder.newFile();
        try (InputStream is = Resources.getResource("nnmi_traps").openStream()) {
            Files.copy(is, nnmiTraps.toPath(), StandardCopyOption.REPLACE_EXISTING);
        }

        // Playback and gather all of the events
        TrapLogReplayer trapLogReplayer = new TrapLogReplayer(nnmiTraps);
        List<TrapLogReplayer.Trap> traps = new LinkedList<>();
        trapLogReplayer.streamTraps(traps::add);

        // We should two traps
        assertThat(traps, hasSize(equalTo(2)));

        // Verify the traps
        TrapLogReplayer.Trap ospfOriginateLsaTrap =  traps.get(0);
        assertThat(ospfOriginateLsaTrap.getName(), equalTo("ospfOriginateLsa"));
        assertThat(ospfOriginateLsaTrap.getTrapTypeOid(), equalTo(".1.3.6.1.2.1.14.16.2.12"));
        assertThat(ospfOriginateLsaTrap.getReceivedAt(), equalTo("November 19, 2018 12:00:53 AM EST"));
        assertThat(ospfOriginateLsaTrap.getVersion(), equalTo("SNMPv2c"));
        assertThat(ospfOriginateLsaTrap.getVarbinds(), hasSize(equalTo(8)));

        TrapLogReplayer.Trap vmwVmHBDetectedTrap =  traps.get(1);
        assertThat(vmwVmHBDetectedTrap.getName(), equalTo("vmwVmHBDetected"));
        assertThat(vmwVmHBDetectedTrap.getEnterpriseOid(), equalTo(".1.3.6.1.4.1.6876.4.1"));
        assertThat(vmwVmHBDetectedTrap.getAgentAddress(), equalTo("10.0.0.1"));
        assertThat(vmwVmHBDetectedTrap.getVarbinds(), hasSize(equalTo(3)));

        // Now convert these to PDUs
        PDU ospfOriginateLsaPdu = trapLogReplayer.toPdu(ospfOriginateLsaTrap);
        assertThat(ospfOriginateLsaPdu, notNullValue());

        PDU vmwVmHBDetectedPdu = trapLogReplayer.toPdu(vmwVmHBDetectedTrap);
        assertThat(vmwVmHBDetectedPdu, notNullValue());
    }
}
