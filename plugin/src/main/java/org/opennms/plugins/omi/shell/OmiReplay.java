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

package org.opennms.plugins.omi.shell;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;

import org.apache.karaf.shell.api.action.Action;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.opennms.plugins.nnmi.TrapLogReplayer;
import org.snmp4j.CommunityTarget;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.transport.DefaultUdpTransportMapping;

@Command(scope = "omi", name = "replay", description = "Replay NNMI trap log")
@Service
public class OmiReplay implements Action {

    @Option(name = "-o", description = "opennms host")
    private String opennmsHost = "127.0.0.1";

    @Option(name = "-f", description = "log file", required = true)
    private String logFile;

    @Override
    public Object execute() throws Exception {
        final File trapLogFile = new File(logFile);
        if (!trapLogFile.canRead()) {
            throw new IOException("Cannot read: " + logFile);
        }

        // Create Transport Mapping
        TransportMapping<UdpAddress> transport = new DefaultUdpTransportMapping();
        transport.listen();

        // Create Target
        CommunityTarget cTarget = new CommunityTarget();
        cTarget.setCommunity(new OctetString("public"));
        cTarget.setVersion(SnmpConstants.version2c);
        cTarget.setAddress(new UdpAddress(InetAddress.getByName(opennmsHost), 162));
        cTarget.setTimeout(5000);
        cTarget.setRetries(2);

        Snmp snmp = new Snmp(transport);

        try {
            TrapLogReplayer trapLogReplayer = new TrapLogReplayer(trapLogFile);
            trapLogReplayer.streamPdus((trap,pdu)-> {
                System.out.println("Sending " + trap.getName());
                // Send the PDU
                try {
                    snmp.send(pdu, cTarget);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
        } finally {
            snmp.close();
        }

        return null;
    }
}