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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.opennms.integration.api.v1.config.events.AlarmData;
import org.opennms.integration.api.v1.config.events.EventConfExtension;
import org.opennms.integration.api.v1.config.events.EventDefinition;
import org.opennms.integration.api.v1.config.events.LogMessage;
import org.opennms.integration.api.v1.config.events.LogMsgDestType;
import org.opennms.integration.api.v1.config.events.Mask;
import org.opennms.integration.api.v1.config.events.MaskElement;
import org.opennms.integration.api.v1.config.events.Parameter;
import org.opennms.integration.api.v1.config.events.Varbind;
import org.opennms.integration.api.v1.model.Severity;
import org.opennms.plugins.omi.model.OmiTrapDef;
import org.opennms.plugins.omi.snmp.TrapHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OmiEventConfExtension implements EventConfExtension {

    private static final Logger LOG = LoggerFactory.getLogger(OmiEventConfExtension.class);

    private final OmiDefinitionProvider omiDefinitionProvider;

    public OmiEventConfExtension(OmiDefinitionProvider omiDefinitionProvider) {
        this.omiDefinitionProvider = Objects.requireNonNull(omiDefinitionProvider);
    }

    @Override
    public List<EventDefinition> getEventDefinitions() {
        return omiDefinitionProvider.getTrapDefs().stream()
                .flatMap(def -> toEventDefinitions(def).stream())
                .collect(Collectors.toList());
    }

    private List<EventDefinition> toEventDefinitions(OmiTrapDef omiTrapDef) {
        final Severity severity = Severity.MINOR;
        final LogMessage logMessage = new LogMessage() {
            @Override
            public String getContent() {
                return omiTrapDef.getLabel();
            }
            @Override
            public LogMsgDestType getDestination() {
                return LogMsgDestType.LOGNDISPLAY;
            }
        };
        /*
         <mask>
         <maskelement>
            <mename>id</mename>
            <mevalue>.1.3.6.1.4.1.9.10.17.3</mevalue>
         </maskelement>
         <maskelement>
            <mename>generic</mename>
            <mevalue>6</mevalue>
         </maskelement>
         <maskelement>
            <mename>specific</mename>
            <mevalue>1</mevalue>
         </maskelement>
      </mask>
         */

        TrapHelper.TrapInfo trapInfo = TrapHelper.getTrapInfo(omiTrapDef.getTrapTypeOid());
        LOG.info("Generated trap info: {}", trapInfo);
        MaskElement idMask = new MaskElement() {
            @Override
            public String getName() {
                return "id";
            }

            @Override
            public List<String> getValues() {
                // NOTE: Prepend the "." since the toString on the OIDs doesn't add it
                return Arrays.asList("." + trapInfo.getEnterpriseId().toString());
            }
        };
        MaskElement genericMask = new MaskElement() {
            @Override
            public String getName() {
                return "generic";
            }

            @Override
            public List<String> getValues() {
                return Arrays.asList(Integer.toString(trapInfo.getGeneric()));
            }
        };
        MaskElement specificMask = new MaskElement() {
            @Override
            public String getName() {
                return "specific";
            }

            @Override
            public List<String> getValues() {
                return Arrays.asList(Integer.toString(trapInfo.getSpecific()));
            }
        };

        final Mask mask = new Mask() {
            @Override
            public List<MaskElement> getMaskElements() {
                return Arrays.asList(idMask, genericMask, specificMask);
            }

            @Override
            public List<Varbind> getVarbinds() {
                return Collections.emptyList();
            }
        };

        EventDefinition def = new EventDefinition() {
            public int getPriority() {
                return 1000;
            }

            public String getUei() {
                return "uei.opennms.org/omi/trapTest";
            }

            public String getLabel() {
                return omiTrapDef.getLabel();
            }

            public Severity getSeverity() {
                return severity;
            }

            public String getDescription() {
                return omiTrapDef.getLabel();
            }

            public LogMessage getLogMessage() {
                return logMessage;
            }

            public AlarmData getAlarmData() {
                return null;
            }

            public Mask getMask() {
                return mask;
            }

            public List<Parameter> getParameters() {
                return Collections.emptyList();
            }
        };
        return Arrays.asList(def);
    }
}
