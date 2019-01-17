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

import org.snmp4j.smi.OID;

public class OmiSnmpConstants {

    public static final OID authAddr = new OID(".1.3.6.1.4.1.9.2.1.5.0");
    public static final OID authenticationFailure = new OID(".1.3.6.1.6.3.1.1.5.5");

    public static final OID ifIndex = new OID(".1.3.6.1.2.1.2.2.1.1");
    public static final OID ifAdminStatus = new OID(".1.3.6.1.2.1.2.2.1.7"); // up(1),down(2),testing(3)
    public static final OID ifOperStatus = new OID(".1.3.6.1.2.1.2.2.1.8"); // up(1),down(2),testing(3)
    public static final OID ifAlias = new OID(".1.3.6.1.2.1.31.1.1.1.18");
    public static final OID ifDescr = new OID(".1.3.6.1.2.1.2.2.1.2");
    public static final OID ifName = new OID(".1.3.6.1.2.1.31.1.1.1.2");

    public static final OID linkUp = new OID(".1.3.6.1.6.3.1.1.5.4");
    public static final OID linkDown = new OID(".1.3.6.1.6.3.1.1.5.3");

    public static final OID coldStart = new OID(".1.3.6.1.6.3.1.1.5.1");
    public static final OID warmStart = new OID(".1.3.6.1.6.3.1.1.5.2");

    public static final OID rttMonNotificationsPrefix = new OID(".1.3.6.1.4.1.9.9.42.2");
    public static final OID rttMonNotification = new OID(".1.3.6.1.4.1.9.9.42.2.0.5");
    public static final OID rttMonCtrlAdminTag = new OID(".1.3.6.1.4.1.9.9.42.1.2.1.1.3");
    public static final OID rttMonHistoryCollectionAddress = new OID(".1.3.6.1.4.1.9.9.42.1.4.1.1.5");
    public static final OID rttMonReactVar = new OID(".1.3.6.1.4.1.9.9.42.1.2.19.1.2");
    public static final OID rttMonReactOccurred = new OID(".1.3.6.1.4.1.9.9.42.1.2.19.1.10");
    public static final OID rttMonReactValue = new OID(".1.3.6.1.4.1.9.9.42.1.2.19.1.9");
    public static final OID rttMonReactThresholdRising = new OID(".1.3.6.1.4.1.9.9.42.1.2.19.1.5");
    public static final OID rttMonReactThresholdFalling = new OID(".1.3.6.1.4.1.9.9.42.1.2.19.1.6");
    public static final OID rttMonEchoAdminLSPSelector = new OID(".1.3.6.1.4.1.9.9.42.1.2.2.1.33");
}
