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

public class VarbindConstraint {
    private int vbOrdinal;
    private String valueExpression;
    public int getVbOrdinal() {
        return vbOrdinal;
    }
    public void setVbOrdinal(int vbOrdinal) {
        this.vbOrdinal = vbOrdinal;
    }
    public String getValueExpression() {
        return valueExpression;
    }
    public void setValueExpression(String valueExpression) {
        this.valueExpression = valueExpression;
    }
    
    public VarbindConstraint(final int vbOrdinal, final String valueExpression) {
        this.vbOrdinal = vbOrdinal;
        this.valueExpression = valueExpression;
    }
    
    public boolean equals(Object o) {
        if (o instanceof VarbindConstraint) {
            VarbindConstraint other = (VarbindConstraint)o;
            if (this.vbOrdinal != other.getVbOrdinal()) return false;
            if (this.valueExpression != null && !this.valueExpression.equals(other.getValueExpression())) return false;
            if (this.valueExpression == null && other.getValueExpression() != null) return false;
            if (this.valueExpression != null && other.getValueExpression() == null) return false;
        }
        return true;
    }
    
    public String toString() {
        StringBuilder sb = new StringBuilder("VarbindConstraint{ #");
        sb.append(vbOrdinal)
          .append(" = \"")
          .append(valueExpression)
          .append(" \" }");
        return sb.toString();
    }
}
