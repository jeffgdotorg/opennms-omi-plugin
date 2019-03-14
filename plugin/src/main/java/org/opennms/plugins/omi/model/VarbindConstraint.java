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

public class VarbindConstraint {
    private int vbOrdinal;
    private List<String> valueExpressions;
    public int getVbOrdinal() {
        return vbOrdinal;
    }
    public void setVbOrdinal(int vbOrdinal) {
        this.vbOrdinal = vbOrdinal;
    }
    public List<String> getValueExpressions() {
        return valueExpressions;
    }
    public void setValueExpressions(List<String> valueExpressions) {
        this.valueExpressions = valueExpressions;
    }
    
    public void addValueExpression(String valueExpression) {
        valueExpressions.add(valueExpression);
    }
    
    public VarbindConstraint(final int vbOrdinal, final String valueExpression) {
        this.vbOrdinal = vbOrdinal;
        final List<String> valueExpressions = new ArrayList<>();
        valueExpressions.add(valueExpression);
        this.valueExpressions = valueExpressions;
    }
    public VarbindConstraint(final int vbOrdinal, final List<String> valueExpressions) {
        this.vbOrdinal = vbOrdinal;
        this.valueExpressions = valueExpressions;
    }
    
    public boolean equals(Object o) {
        if (o instanceof VarbindConstraint) {
            VarbindConstraint other = (VarbindConstraint)o;
            if (this.vbOrdinal != other.getVbOrdinal()) return false;
            if (this.valueExpressions.size() != other.getValueExpressions().size()) return false;
            for (int i = 0; i < this.valueExpressions.size(); i++) {
                if (this.valueExpressions.get(i) != null && !this.valueExpressions.get(i).equals(other.getValueExpressions().get(i))) return false;
                if (this.valueExpressions.get(i) == null && other.getValueExpressions().get(i) != null) return false;
                if (this.valueExpressions.get(i) != null && other.getValueExpressions().get(i) == null) return false;
            }
        }
        return true;
    }
    
    public String toString() {
        StringBuilder sb = new StringBuilder("VarbindConstraint{ #");
        sb.append(vbOrdinal)
          .append(" = [ ");
        for (int i = 0; i < valueExpressions.size(); i++) {
            sb.append("\"")
              .append(valueExpressions.get(i))
              .append("\"");
            if (i < valueExpressions.size() - 1) {
                sb.append(", ");
            }
        }
          sb.append(" ]")
          .append(" }");
        return sb.toString();
    }
}
