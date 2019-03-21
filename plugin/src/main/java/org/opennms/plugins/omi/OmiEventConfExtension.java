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
import java.util.regex.PatternSyntaxException;
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
import org.opennms.plugins.omi.model.MatchType;
import org.opennms.plugins.omi.model.OmiTrapDef;
import org.opennms.plugins.omi.model.VarbindConstraint;
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
        LOG.debug("Top of getEventDefinitions");
        final List<EventDefinition> suppressMatchDefinitions = new ArrayList<>();
        final List<EventDefinition> msgMatchDefinitions = new ArrayList<>();
        final List<EventDefinition> suppressUnmatchDefinitions = new ArrayList<>();
        final List<EventDefinition> msgUnmatchDefinitions = new ArrayList<>();
        
        for (OmiTrapDef omiTrapDef : omiDefinitionProvider.getTrapDefs()) {
            if (omiTrapDef.getMatchType() == MatchType.SUPP_MATCH) {
                suppressMatchDefinitions.add(toEventDefinition(omiTrapDef));
            } else if (omiTrapDef.getMatchType() == MatchType.MSG_MATCH) {
                msgMatchDefinitions.add(toEventDefinition(omiTrapDef));
            } else if (omiTrapDef.getMatchType() == MatchType.SUPP_UNMATCH) {
                suppressUnmatchDefinitions.add(toEventDefinition(omiTrapDef));
            } else if (omiTrapDef.getMatchType() == MatchType.MSG_UNMATCH) {
                msgUnmatchDefinitions.add(toEventDefinition(omiTrapDef));
            }
        }
        
        LOG.debug("Accumulated event counts by match-type: SUPP_MATCH={} MSG_MATCH={} SUPP_UNMATCH={} MSG_UNMATCH={}", suppressMatchDefinitions.size(), msgMatchDefinitions.size(), suppressUnmatchDefinitions.size(), msgUnmatchDefinitions.size());
        
        final List<EventDefinition> orderedEventDefinitions = new ArrayList<>();
        orderedEventDefinitions.addAll(suppressMatchDefinitions);
        orderedEventDefinitions.addAll(msgMatchDefinitions);
        orderedEventDefinitions.addAll(suppressUnmatchDefinitions);
        orderedEventDefinitions.addAll(msgUnmatchDefinitions);
        
        LOG.debug("Returning {} ordered event definitions", orderedEventDefinitions.size());
        return orderedEventDefinitions;
    }
    
    private EventDefinition toEventDefinition(OmiTrapDef omiTrapDef) {
        final Severity severity = toOnmsSeverity(omiTrapDef.getSeverity());
        final LogMessage logMessage = new LogMessage() {
            @Override
            public String getContent() {
                if (omiTrapDef.getText() == null) {
                    return replacePlaceholderTokens(omiTrapDef.getLabel());
                } else {
                    return replacePlaceholderTokens(omiTrapDef.getText());                    
                }
            }
            @Override
            public LogMsgDestType getDestination() {
                if (omiTrapDef.isServerLogOnly()) {
                    return LogMsgDestType.LOGONLY;
                }
                if (omiTrapDef.getMatchType() == MatchType.MSG_MATCH) {
                    return LogMsgDestType.LOGNDISPLAY;
                }
                if (omiTrapDef.getMatchType() == MatchType.MSG_UNMATCH) {
                    return LogMsgDestType.LOGNDISPLAY;
                }
                if (omiTrapDef.getMatchType() == MatchType.SUPP_MATCH) {
                    return LogMsgDestType.DONOTPERSIST;
                }
                if (omiTrapDef.getMatchType() == MatchType.SUPP_UNMATCH) {
                    return LogMsgDestType.DONOTPERSIST;
                }
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
        final List<Varbind> varbinds = new ArrayList<>();
        if (! omiTrapDef.getVarbindConstraints().isEmpty()) {
            for (VarbindConstraint dtoVb : omiTrapDef.getVarbindConstraints()) {
                final Varbind vb = new Varbind() {
                    public Integer getNumber() {
                        return dtoVb.getVbOrdinal();
                    }
                    public List<String> getValues() {
                        final StringBuilder vbSb = new StringBuilder();
                        final List<String> vbValues = new ArrayList<>();
                        for (String inValue : dtoVb.getValueExpressions()) {
                            if (isGratuitouslyRegexedInteger(inValue)) {
                                LOG.debug("Varbind constraint value '{}' is a gratuitously-anchored integer value. Extracting and using sans regex.");
                                vbSb.append(inValue.substring(1, inValue.length() - 1));
                            } else if (isLikelyAndValidRegex(inValue)) {
                                LOG.debug("Varbind constraint value '{}' starts and/or ends with ^ / $, and compiles as a Pattern. Marking as a regex in eventconf.", inValue);
                                vbSb.append("~").append(inValue);
                            } else {
                                vbSb.append(inValue);
                            }
                            vbValues.add(vbSb.toString());
                        }
                        return vbValues;
                    }
                    public String getTextualConvention() {
                        // TODO should this be null or the empty string?
                        return null;
                    }
                };
                varbinds.add(vb);
            }
        }
        
        final Mask mask = maskElements.isEmpty() ? null : new Mask() {
            @Override
            public List<MaskElement> getMaskElements() {
                return maskElements;
            }

            @Override
            public List<Varbind> getVarbinds() {
                return varbinds;
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
        if (omiTrapDef.getObject() != null) {
            final Parameter objectParameter = new Parameter() {
                @Override
                public String getName() {
                    return "Object";
                }
                @Override
                public String getValue() {
                    return replacePlaceholderTokens(omiTrapDef.getObject());
                }
                @Override
                public boolean shouldExpand() {
                    return true;
                }
            };
            parameters.add(objectParameter);
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

            public String getOperatorInstructions() {
                if (omiTrapDef.getHelpText() != null) {
                    return omiTrapDef.getHelpText().replace("\n", "&0xa;");
                }
                return omiTrapDef.getHelpText();
            }
        };
        return def;
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
    
    public static boolean isGratuitouslyRegexedInteger(String string) {
        if (string == null) {
            return false;
        }
        if (string.startsWith("^") && string.endsWith("$")) {
            String middle = string.substring(1, string.length()-1);
            if (middle.matches("^\\d+$")) {
                return true;
            }
        }
        return false;
    }
    
    public static boolean isLikelyAndValidRegex(String string) {
        if (string == null) {
            return false;
        }
        boolean result = false;
        if (string.startsWith("^") || string.endsWith("$")) {
            try {
                Pattern.compile(string);
                result = true;
            } catch (PatternSyntaxException pse) {
                LOG.warn("Varbind constraint value '{}' looks regex-ish but does not compile.");
            }
        }
        return result;
    }
}
