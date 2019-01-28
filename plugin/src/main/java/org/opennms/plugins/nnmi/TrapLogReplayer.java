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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Queue;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.snmp4j.PDU;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.IpAddress;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.TimeTicks;
import org.snmp4j.smi.Variable;
import org.snmp4j.smi.VariableBinding;

public class TrapLogReplayer {

    private final File trapLogFile;
    private Trap trapInProgress;
    private Queue<Trap> trapsToPush = new ArrayBlockingQueue<>(100);

    public TrapLogReplayer(File trapLogFile) {
        Objects.requireNonNull(trapLogFile);
        this.trapLogFile = trapLogFile;
    }

    public void streamTraps(Consumer<Trap> trapConsumer) throws IOException {
        try (FileReader fileReader = new FileReader(this.trapLogFile);
             BufferedReader reader = new BufferedReader(fileReader);) {
            String line = reader.readLine();
            while (line != null) {
                handleLine(line);
                maybePushTrap(trapConsumer);
                line = reader.readLine();
            }
        }

        if (trapInProgress != null) {
            // We're all done, push what we have
            trapsToPush.add(trapInProgress);
        }
        maybePushTrap(trapConsumer);
    }

    public void streamPdus(BiConsumer<Trap, PDU> pduConsumer) throws IOException {
        streamTraps(t -> pduConsumer.accept(t, toPdu(t)));
    }

    private static Pattern TRAP_LINE_PATTERN = Pattern.compile("Trap (.+) \\((.+)\\) at (.+) from (.+)$");
    private static Pattern VERSION_LINE_PATTERN = Pattern.compile("Version: (.+)$");
    private static Pattern STATE_LINE_PATTERN = Pattern.compile("state=(.+) type=(.+) oid=(.+) value=(.+)$");
    private static Pattern ENTERPRISE_OID_LINE_PATTERN = Pattern.compile("Enterprise OID: (.+)$");
    private static Pattern AGENT_ADDRESS_LINE_PATTERN = Pattern.compile("Agent address: (.+)$");

    private void handleLine(String line) {
        Matcher m = TRAP_LINE_PATTERN.matcher(line);
        if (m.matches()) {
            if (trapInProgress != null) {
                // We've hit a new trap, push the previous one
                trapsToPush.add(trapInProgress);
            }
            trapInProgress = new Trap();

            trapInProgress.name = m.group(1);
            trapInProgress.trapTypeOid = m.group(2);
            trapInProgress.receivedAt = m.group(3);
            trapInProgress.receivedFrom = m.group(4);
            return;
        }

        m = VERSION_LINE_PATTERN.matcher(line);
        if (m.matches()) {
            trapInProgress.version = m.group(1);
        }

        m = STATE_LINE_PATTERN.matcher(line);
        if (m.matches()) {
            TrapVarbind varbind = new TrapVarbind();
            varbind.state = m.group(1);
            varbind.type = m.group(2);
            varbind.oid = m.group(3);
            varbind.value = m.group(4);
            trapInProgress.varbinds.add(varbind);
        }

        m = ENTERPRISE_OID_LINE_PATTERN.matcher(line);
        if (m.matches()) {
            trapInProgress.enterpriseOid = m.group(1);
        }

        m = AGENT_ADDRESS_LINE_PATTERN.matcher(line);
        if (m.matches()) {
            trapInProgress.agentAddress = m.group(1);
        }
    }

    private void maybePushTrap(Consumer<Trap> trapConsumer) {
        Trap trap = trapsToPush.poll();
        while(trap != null) {
            trapConsumer.accept(trap);
            trap = trapsToPush.poll();
        }
    }

    public static PDU toPdu(Trap t) {

        final PDU trap = new PDU();
        trap.setType(PDU.TRAP);
        if ("SNMPv2c".equals(t.version)) {
            // All the info is already in the varbinds
        } else if ("SNMPv1".equals(t.version)) {
            trap.add(new VariableBinding(SnmpConstants.sysUpTime, new TimeTicks(1L)));
            trap.add(new VariableBinding(SnmpConstants.snmpTrapOID, new OID(t.getTrapTypeOid())));
        } else {
            throw new IllegalStateException("Unsupported version: " + t.version);
        }
        for (TrapVarbind vb : t.getVarbinds()) {
            trap.add(new VariableBinding(new OID(vb.getOid()), toVbValue(vb)));
        }
        return trap;
    }

    public static Variable toVbValue(TrapVarbind vb) {
        switch(vb.getType()) {
            case "OBJECT IDENTIFIER":
                return new OID(vb.value);
            case "TimeTicks":
                return new TimeTicks(Long.parseLong(vb.value));
            case "IpAddress":
                return new IpAddress(vb.value);
            case "INTEGER":
                return new Integer32(Integer.parseInt(vb.value));
            case "OCTET STRING":
                return new OctetString(vb.value);
            default:
                throw new IllegalStateException("Unsupported VB type: " + vb.getType());
        }
    }

    public static class Trap {
        private String name;
        private String trapTypeOid;
        private String receivedAt;
        private String receivedFrom;

        private String enterpriseOid;
        private String agentAddress;

        private String version;
        private List<TrapVarbind> varbinds = new LinkedList<>();

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getTrapTypeOid() {
            return trapTypeOid;
        }

        public void setTrapTypeOid(String trapTypeOid) {
            this.trapTypeOid = trapTypeOid;
        }

        public String getReceivedAt() {
            return receivedAt;
        }

        public void setReceivedAt(String receivedAt) {
            this.receivedAt = receivedAt;
        }

        public String getReceivedFrom() {
            return receivedFrom;
        }

        public void setReceivedFrom(String receivedFrom) {
            this.receivedFrom = receivedFrom;
        }

        public String getVersion() {
            return version;
        }

        public void setVersion(String version) {
            this.version = version;
        }

        public List<TrapVarbind> getVarbinds() {
            return varbinds;
        }

        public void setVarbinds(List<TrapVarbind> varbinds) {
            this.varbinds = varbinds;
        }

        public String getEnterpriseOid() {
            return enterpriseOid;
        }

        public void setEnterpriseOid(String enterpriseOid) {
            this.enterpriseOid = enterpriseOid;
        }

        public String getAgentAddress() {
            return agentAddress;
        }

        public void setAgentAddress(String agentAddress) {
            this.agentAddress = agentAddress;
        }
    }

    public static class TrapVarbind {
        private String state;
        private String type;
        private String oid;
        private String value;

        public String getState() {
            return state;
        }

        public void setState(String state) {
            this.state = state;
        }

        public String getType() {
            return type;
        }

        public void setType(String type) {
            this.type = type;
        }

        public String getOid() {
            return oid;
        }

        public void setOid(String oid) {
            this.oid = oid;
        }

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }
    }

}
