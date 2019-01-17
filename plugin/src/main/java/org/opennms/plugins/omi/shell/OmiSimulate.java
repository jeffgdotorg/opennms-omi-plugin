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

import java.net.InetAddress;
import java.util.Arrays;
import java.util.List;

import org.apache.karaf.shell.api.action.Action;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.opennms.plugins.omi.OmiDefinitionProvider;
import org.opennms.plugins.omi.OmiSnmpConstants;
import org.opennms.plugins.omi.model.OmiTrapDef;
import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.TimeTicks;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;

@Command(scope = "omi", name = "simulate", description = "Generate traps.")
@Service
public class OmiSimulate implements Action {

    @Reference
    private OmiDefinitionProvider omiDefinitionProvider;

    @Option(name = "-o", description = "opennms host")
    private String opennmsHost;

    @Override
    public Object execute() throws Exception {
        System.out.println("Generating traps...");
        for (OmiTrapDef trapDef : omiDefinitionProvider.getTrapDefs()) {
            final List<PDU> pdus = toPDUs(trapDef);
            for (PDU pdu : pdus) {
                sendSnmpTrap(pdu);
            }
        }
        return null;
    }

    private List<PDU> toPDUs(OmiTrapDef omiTrapDef) {
        // TODO:  Generate PDUs from the OMI trap defs

        final PDU trap = new PDU();
        trap.setType(PDU.TRAP);
        trap.add(new VariableBinding(SnmpConstants.sysUpTime, new TimeTicks(1L)));
        trap.add(new VariableBinding(SnmpConstants.snmpTrapOID, OmiSnmpConstants.rttMonNotification));
        trap.add(new VariableBinding(OmiSnmpConstants.rttMonCtrlAdminTag, new Integer32(0)));
        trap.add(new VariableBinding(OmiSnmpConstants.rttMonHistoryCollectionAddress, new Integer32(0)));
        trap.add(new VariableBinding(OmiSnmpConstants.rttMonReactVar, new Integer32(0)));
        trap.add(new VariableBinding(OmiSnmpConstants.rttMonReactOccurred, new Integer32(0)));
        trap.add(new VariableBinding(OmiSnmpConstants.rttMonReactValue, new Integer32(0)));
        trap.add(new VariableBinding(OmiSnmpConstants.rttMonReactThresholdRising, new Integer32(0)));
        trap.add(new VariableBinding(OmiSnmpConstants.rttMonReactThresholdFalling, new Integer32(0)));
        trap.add(new VariableBinding(OmiSnmpConstants.rttMonEchoAdminLSPSelector, new Integer32(0)));

        return Arrays.asList(trap);
    }

    private void sendSnmpTrap(PDU pdu) {
        try {
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

            // Send the PDU
            Snmp snmp = new Snmp(transport);
            snmp.send(pdu, cTarget);
            snmp.close();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}