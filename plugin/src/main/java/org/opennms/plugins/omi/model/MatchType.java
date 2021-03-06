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

public enum MatchType {
    SUPP_UNMATCH (1, "Suppress Unmatched"),
    SUPP_MATCH (2, "Suppress Matched"),
    MSG_MATCH (3, "Message Matched"),
    MSG_UNMATCH (4, "Message Unmatched"),
    OTHER (5, "Other");
    
    private int id;
    private String label;
    
    MatchType(final int id, final String label) {
        this.id = id;
        this.label = label;
    }
    
    public int getId() {
        return id;
    }
    
    public String getLabel() {
        return label;
    }
    
    public static MatchType get(String type) {
        for (MatchType t : MatchType.values()) {
            if (t.getLabel().equalsIgnoreCase(type)) {
                return t;
            }
        }
        return MatchType.OTHER;
    }
}
