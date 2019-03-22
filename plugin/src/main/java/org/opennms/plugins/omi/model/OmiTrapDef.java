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

package org.opennms.plugins.omi.model;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OmiTrapDef {

    private MatchType matchType;
    private String label;
    private String enterpriseId;
    private Integer generic;
    private Integer specific;
    List<VarbindConstraint> varbindConstraints = new ArrayList<>();
    private String severity;
    private String text;
    private String object;
    private String application;
    private String msgGrp;
    private String msgKey;
    private String msgKeyRelation;
    private String helpText;
    private boolean serverLogOnly = false;

    private String trapTypeOid;
    
    private static final Logger LOG = LoggerFactory.getLogger(OmiTrapDef.class);

    public MatchType getMatchType() {
        return matchType;
    }

    public void setMatchType(MatchType matchType) {
        this.matchType = matchType;
    }

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public String getTrapTypeOid() {
        return trapTypeOid;
    }

    public void setTrapTypeOid(String trapTypeOid) {
        this.trapTypeOid = trapTypeOid;
    }

    public String getEnterpriseId() {
        return enterpriseId;
    }

    public void setEnterpriseId(String enterpriseId) {
        this.enterpriseId = enterpriseId;
    }

    public Integer getGeneric() {
        return generic;
    }

    public void setGeneric(Integer generic) {
        this.generic = generic;
    }

    public Integer getSpecific() {
        return specific;
    }

    public void setSpecific(Integer specific) {
        this.specific = specific;
    }

    public List<VarbindConstraint> getVarbindConstraints() {
        return varbindConstraints;
    }

    public void setVarbindConstraints(List<VarbindConstraint> varbindConstraints) {
        this.varbindConstraints = varbindConstraints;
    }
    
    public void addVarbindConstraint(VarbindConstraint vbc) {
        varbindConstraints.add(vbc);
    }
    
    public void addVarbindConstraints(List<VarbindConstraint> vbcs) {
        varbindConstraints.addAll(vbcs);
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getText() {
        return text;
    }

    public void setText(String text) {
        this.text = text;
    }

    public String getObject() {
        return object;
    }

    public void setObject(String object) {
        this.object = object;
    }

    public String getApplication() {
        return application;
    }

    public void setApplication(String application) {
        this.application = application;
    }

    public String getMsgGrp() {
        return msgGrp;
    }

    public void setMsgGrp(String msgGrp) {
        this.msgGrp = msgGrp;
    }

    public String getMsgKey() {
        return msgKey;
    }

    public void setMsgKey(String msgKey) {
        this.msgKey = msgKey;
    }

    public String getMsgKeyRelation() {
        return msgKeyRelation;
    }

    public void setMsgKeyRelation(String msgKeyRelation) {
        this.msgKeyRelation = msgKeyRelation;
    }

    public String getHelpText() {
        return helpText;
    }

    public void setHelpText(String helpText) {
        this.helpText = helpText;
    }
    
    public boolean isServerLogOnly() {
        return serverLogOnly;
    }

    public void setServerLogOnly(boolean serverLogOnly) {
        this.serverLogOnly = serverLogOnly;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder("OmiTrapDef {")
            .append(" matchType=").append(matchType == null ? "null" : matchType.toString())
            .append(", label=").append(label)
            .append(", enterpriseId=").append(enterpriseId)
            .append(", generic=").append(generic)
            .append(", specific=").append(specific)
            .append(", varbindConstraints={");
        if (varbindConstraints != null && !varbindConstraints.isEmpty()) {
            for (VarbindConstraint vbc : varbindConstraints) {
                sb.append(vbc.toString()).append(",");
            }
        }
        sb.append("}")
            .append(", severity=").append(severity)
            .append(", text=").append(text)
            .append(", object=").append(object)
            .append(", application=").append(application)
            .append(", msgGrp=").append(msgGrp)
            .append(", helpText=").append(makeOneLiner(helpText))
            .append(", trapTypeOid=").append(trapTypeOid);
        sb.append("}");
        return sb.toString();
    }
    
    private static String makeOneLiner(String input) {
        if (input == null) {
            return "null";
        }
        String output = input;
        output = input.replaceAll("\n", "[NL]").replaceAll("\r", "[CR]");
        if (output.length() > 64) {
            String firstPart = output.substring(0, 30);
            String lastPart = output.substring(output.length() - 30, output.length());
            output = firstPart + "…" + lastPart;
        }
        return output;
    }
}
