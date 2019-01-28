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
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

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

import com.google.common.io.Files;

@Command(scope = "omi", name = "replay", description = "Replay NNMI trap log")
@Service
public class OmiReplay implements Action {

    @Option(name = "-o", description = "opennms host")
    private String opennmsHost = "127.0.0.1";

    @Option(name = "-f", description = "log file", required = true)
    private String logFile;

    @Option(name = "-i", description = "import file - used to generate an import instead of sending the traps")
    private String importFile;

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
            AtomicLong trapCounter = new AtomicLong(0);
            trapLogReplayer.streamPdus((trap,pdu)-> {
                if (trapCounter.incrementAndGet() % 1000  == 0) {
                    System.out.printf("Processed %d traps.\n", trapCounter.get());
                }
                if (importFile != null) {
                    // noop
                    return;
                }
                System.out.printf("Sending %s for %s\n", trap.getName(), trap.getReceivedFrom());
                // Send the PDU
                try {
                    snmp.send(pdu, cTarget);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });


            if (importFile != null) {
                final String provImport = generateImport(trapLogReplayer.getHostnameToAddress());
                System.out.printf("Writing requisition for %d nodes to %s.\n", trapLogReplayer.getHostnameToAddress().size(), importFile);
                Files.write(provImport.getBytes(StandardCharsets.UTF_8), new File(importFile));
            }
        } finally {
            snmp.close();
        }

        System.out.println();
        return null;
    }

    private String generateImport(Map<String, InetAddress> hostnameToAddress) {
        final StringBuilder sb = new StringBuilder();
        sb.append("<model-import xmlns=\"http://xmlns.opennms.org/xsd/config/model-import\" date-stamp=\"2019-01-28T13:48:30.302-05:00\" foreign-source=\"NODES\" last-import=\"2019-01-28T13:49:02.394-05:00\">\n");
        for (Map.Entry<String, InetAddress> entry : hostnameToAddress.entrySet()) {
            sb.append(String.format("<node foreign-id=\"%s\" node-label=\"%s\">\n" +
                    "      <interface ip-addr=\"%s\" status=\"1\" snmp-primary=\"N\"/>\n" +
                    "   </node>\n", entry.getKey(), entry.getKey(), entry.getValue().getHostAddress()));
        }
        sb.append("</model-import>");
        return sb.toString();
    }
}
