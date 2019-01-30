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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.opennms.integration.api.v1.config.events.AlarmData;
import org.opennms.integration.api.v1.config.events.AlarmType;
import org.opennms.integration.api.v1.config.events.EventConfExtension;
import org.opennms.integration.api.v1.config.events.EventDefinition;
import org.opennms.integration.api.v1.config.events.LogMessage;
import org.opennms.integration.api.v1.config.events.LogMsgDestType;
import org.opennms.integration.api.v1.config.events.ManagedObject;
import org.opennms.integration.api.v1.config.events.Mask;
import org.opennms.integration.api.v1.config.events.MaskElement;
import org.opennms.integration.api.v1.config.events.Parameter;
import org.opennms.integration.api.v1.config.events.UpdateField;
import org.opennms.integration.api.v1.config.events.Varbind;
import org.opennms.integration.api.v1.model.Severity;
import org.opennms.plugins.omi.model.OmiTrapDef;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OmiEventConfExtension implements EventConfExtension {

    public static final String UEI_PREFIX = "uei.opennms.org/omi/";

    private static final Logger LOG = LoggerFactory.getLogger(OmiEventConfExtension.class);

    private static final Pattern PLACEHOLDER_PATTERN = Pattern.compile("<\\$(\\d+)>");

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
        final Severity severity = toOnmsSeverity(omiTrapDef.getSeverity());
        final LogMessage logMessage = new LogMessage() {
            @Override
            public String getContent() {
                return replacePlaceholderTokens(omiTrapDef.getText());
            }
            @Override
            public LogMsgDestType getDestination() {
                return LogMsgDestType.LOGNDISPLAY;
            }
        };


        final List<MaskElement> maskElements = new LinkedList<>();
        if (omiTrapDef.getEnterpriseId() != null) {
            final MaskElement idMask = new MaskElement() {
                @Override
                public String getName() {
                    return "id";
                }

                @Override
                public List<String> getValues() {
                    return Collections.singletonList(omiTrapDef.getEnterpriseId());
                }
            };
            maskElements.add(idMask);
        }
        if (omiTrapDef.getGeneric() != null) {
            final MaskElement genericMask = new MaskElement() {
                @Override
                public String getName() {
                    return "generic";
                }

                @Override
                public List<String> getValues() {
                    return Collections.singletonList(Integer.toString(omiTrapDef.getGeneric()));
                }
            };
            maskElements.add(genericMask);
        }
        if (omiTrapDef.getSpecific() != null) {
            final MaskElement specificMask = new MaskElement() {
                @Override
                public String getName() {
                    return "specific";
                }

                @Override
                public List<String> getValues() {
                    return Collections.singletonList(Integer.toString(omiTrapDef.getSpecific()));
                }
            };
            maskElements.add(specificMask);
        }
        final Mask mask = maskElements.isEmpty() ? null : new Mask() {
            @Override
            public List<MaskElement> getMaskElements() {
                return maskElements;
            }

            @Override
            public List<Varbind> getVarbinds() {
                return Collections.emptyList();
            }
        };

        // Use the placeholder tokens from the text as elements in the reduction key
        final StringBuilder reductionKeySb = new StringBuilder();
        reductionKeySb.append("%uei%:%dpname%:%nodeid%");
        for (String placeholderToken : extractPlaceholderTokens(omiTrapDef.getText())) {
            reductionKeySb.append(":");
            reductionKeySb.append(placeholderToken);
        }
        final String reductionKey = reductionKeySb.toString();

        final AlarmData alarmData = new AlarmData() {
            @Override
            public String getReductionKey() {
                return reductionKey;
            }

            @Override
            public AlarmType getType() {
                return AlarmType.PROBLEM_WITHOUT_RESOLUTION;
            }

            @Override
            public String getClearKey() {
                return null;
            }

            @Override
            public boolean isAutoClean() {
                return false;
            }

            @Override
            public List<UpdateField> getUpdateFields() {
                return Collections.emptyList();
            }

            @Override
            public ManagedObject getManagedObject() {
                return null;
            }
        };

        final List<Parameter> parameters = new LinkedList<>();
        if (omiTrapDef.getApplication() != null) {
            final Parameter applicationParameter = new Parameter() {
                @Override
                public String getName() {
                    return "Application";
                }
                @Override
                public String getValue() {
                    return omiTrapDef.getApplication();
                }
                @Override
                public boolean shouldExpand() {
                    return false;
                }
            };
            parameters.add(applicationParameter);
        }
        if (omiTrapDef.getMsgGrp() != null) {
            final Parameter msgGrpParameter = new Parameter() {
                @Override
                public String getName() {
                    return "MsgGrp";
                }
                @Override
                public String getValue() {
                    return omiTrapDef.getMsgGrp();
                }
                @Override
                public boolean shouldExpand() {
                    return false;
                }
            };
            parameters.add(msgGrpParameter);
        }

        final EventDefinition def = new EventDefinition() {
            public int getPriority() {
                return 1000;
            }

            public String getUei() {
                return UEI_PREFIX + omiTrapDef.getLabel();
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
                return alarmData;
            }

            public Mask getMask() {
                return mask;
            }

            public List<Parameter> getParameters() {
                return parameters;
            }
            
            public String getOperInstruct() {
                return omiTrapDef.getRecommendedAction();
            }
        };
        return Arrays.asList(def);
    }

    public static Severity toOnmsSeverity(String omiSeverity) {
        if (omiSeverity == null) {
            return Severity.INDETERMINATE;
        }
        return Severity.get(omiSeverity.toLowerCase());
    }

    public static String replacePlaceholderTokens(String string) {
        if (string == null) {
            return null;
        }
        final Matcher m = PLACEHOLDER_PATTERN.matcher(string);
        boolean result = m.find();
        if (result) {
            StringBuffer sb = new StringBuffer();
            do {
                m.appendReplacement(sb, String.format("%%parm[#%s]%%", m.group(1)));
                result = m.find();
            } while (result);
            m.appendTail(sb);
            return sb.toString();
        }
        return string;
    }

    public static List<String> extractPlaceholderTokens(String string) {
        if (string == null) {
            return Collections.emptyList();
        }
        final List<String> tokens = new ArrayList<>();
        final Matcher m = PLACEHOLDER_PATTERN.matcher(string);
        while(m.find()) {
            tokens.add(String.format("%%parm[#%s]%%", m.group(1)));
        }
        return tokens;
    }
}
