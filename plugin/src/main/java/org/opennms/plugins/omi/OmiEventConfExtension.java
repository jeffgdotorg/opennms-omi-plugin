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
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

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
    
    public static final String AUTO_ACK_USERNAME = "auto-ack";

    private static final Logger LOG = LoggerFactory.getLogger(OmiEventConfExtension.class);

    private static final Pattern PLACEHOLDER_PATTERN_POLICYVAR = Pattern.compile("<\\$(\\d+|[*#@ACEeFGSsTVXx]|MSG_TEXT|MSG_ID|MSG_NODE_NAME)>");
    private static final Pattern PLACEHOLDER_PATTERN_USERVAR = Pattern.compile("<([A-Za-z][A-Za-z0-9_-]+)>");
    
    private static final Pattern BARE_EMAILADDR_PATTERN = Pattern.compile("([^>:])([^,@ ]+@[^,@ \n]+)\\b");
    
    private static final Pattern BARE_HTTPLINK_PATTERN = Pattern.compile("([^\">])(https?://.*?)([ \n]|$)");
    
    protected static final String TOKEN_ASTERISK_REGEX_EQUIVALENT = ".";
    protected static final String TOKEN_AT_REGEX_EQUIVALENT = "\\w";
    protected static final String TOKEN_HASH_REGEX_EQUIVALENT = "\\d";
    protected static final String TOKEN_UNDERSCORE_REGEX_EQUIVALENT = "(_|/|\\|:|-)";
    protected static final String TOKEN_SLASH_REGEX_EQUIVALENT = "(\\n|\\r)";
    protected static final String TOKEN_S_REGEX_EQUIVALENT = "( |\\t|\\n|\\r)";

    private static final Pattern ASSIGN_ONLY_ACTION_GROUP_PATTERN = Pattern.compile("(?<!\\{1})<(\\[.+\\])(\\.[A-Za-z][A-Za-z0-9_-]+)>");
    private static final Pattern NEGATED_ACTION_GROUP_PATTERN = Pattern.compile("(?<!\\{1})<!(\\[[^\\]]+\\])>");
    private static final Pattern COMPLEX_ACTION_GROUP_PATTERN = Pattern.compile("(?<!\\{1})<(\\d+)?([*@#_/S])(\\.[A-Za-z][A-Za-z0-9_-]+)?>");
    private static final Pattern INNER_GROUPING_PATTERN = Pattern.compile("(?<!\\{1})\\[([^\\]]+)(?<!\\{1})\\]");
    private static final Pattern ALPHA_LC_CHARS_PRECEDED_BY_NON_ALPHANUM = Pattern.compile("(?<=[^A-Za-z0-9]+)([a-z])");

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
        for (EventDefinition eDef : orderedEventDefinitions) {
            LOG.debug("Event: {}", eDef.getUei());
        }
        return orderedEventDefinitions;
    }
    
    private EventDefinition toEventDefinition(OmiTrapDef omiTrapDef) {
        final Severity severity = toOnmsSeverity(omiTrapDef.getSeverity());
        final LogMessage logMessage = new LogMessage() {
            @Override
            public String getContent() {
                if (omiTrapDef.getText() == null) {
                    return replaceUservarPlaceholderTokens(replacePolicyvarPlaceholderTokens(omiTrapDef.getLabel()));
                } else {
                    return replaceUservarPlaceholderTokens(replacePolicyvarPlaceholderTokens(omiTrapDef.getText()));
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
                    return LogMsgDestType.DISCARDTRAPS;
                }
                if (omiTrapDef.getMatchType() == MatchType.SUPP_UNMATCH) {
                    return LogMsgDestType.DISCARDTRAPS;
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
                        String vbString;
                        final List<String> vbValues = new ArrayList<>();
                        for (String inValue : dtoVb.getValueExpressions()) {
                            if (isGratuitouslyRegexedInteger(inValue)) {
                                vbString = inValue.substring(1, inValue.length() - 1);
                                LOG.debug("Varbind #{} constraint value '{}' is a gratuitously-anchored integer value. Extracting and using sans regex in eventconf vbvalue: '{}'.", dtoVb.getVbOrdinal(), inValue, vbString);
                            } else if (looksLiteral(inValue)) {
                                vbString = inValue;
                                LOG.debug("Varbind #{} constraint value '{}' looks literal. Skipping regex transformation.");
                            }
                            else {
                                final String candidateVbString = translateOmiPatternToRegex(inValue);
                                try {
                                    Pattern.compile(candidateVbString);
                                    vbString = "~" + candidateVbString;
                                    LOG.debug("Translated OMi pattern '{}' to regex '{}'", inValue, vbString);
                                } catch (PatternSyntaxException pse) {
                                    LOG.warn("Failed to compile regex '{}' for trap {}. Including as a literal, but this rule will never match.", candidateVbString, omiTrapDef.getLabel());
                                    vbString = "!!BROKEN!! " + candidateVbString;
                                }
                            }
                            vbValues.add(vbString);
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
        // TODO: Replace with a method
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
                    return replacePolicyvarPlaceholderTokens(omiTrapDef.getApplication());
                }
                @Override
                public boolean shouldExpand() {
                    return getValue().contains("%parm[");
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
                    return replacePolicyvarPlaceholderTokens(omiTrapDef.getObject());
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
                int prio = 1000;
                if (omiTrapDef.isCatchAll()) {
                    prio--;
                }
                return prio;
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
                return decorateOperInstruct(omiTrapDef.getHelpText());
            }
        };
        return def;
    }
    
    public static AlarmData toAlarmData(OmiTrapDef trapDef) {
        final String reductionKey, clearKey;
        AlarmType workingAlarmType;
        List<UpdateField> updateFields = new ArrayList<>();
        if (trapDef.getMsgKey() != null) {
            workingAlarmType = AlarmType.PROBLEM;
            reductionKey = replaceUservarPlaceholderTokens(replacePolicyvarPlaceholderTokens(trapDef.getMsgKey()));
        } else {
            workingAlarmType = AlarmType.PROBLEM_WITHOUT_RESOLUTION;
            reductionKey = inferReductionKey(trapDef);
        }
        
        if (trapDef.getMsgKeyRelation() != null) {
            workingAlarmType = AlarmType.RESOLUTION;
            clearKey = replaceUservarPlaceholderTokens(replacePolicyvarPlaceholderTokens(trapDef.getMsgKeyRelation()));
            updateFields.add(new UpdateField() {
                @Override
                public String getName() {
                    return AUTO_ACK_USERNAME;
                }
                @Override
                public boolean isUpdatedOnReduction() {
                    return true;
                }
            });
            updateFields.add(new UpdateField() {
                @Override
                public String getName() {
                    return "now";
                }
                @Override
                public boolean isUpdatedOnReduction() {
                    return true;
                }                
            });
        } else {
            clearKey = null;
        }
        final AlarmType finalAlarmType = workingAlarmType;
        
        return new AlarmData() {

            @Override
            public String getReductionKey() {
                return reductionKey;
            }
            @Override
            public AlarmType getType() {
                return finalAlarmType;
            }
            @Override
            public String getClearKey() {
                return clearKey;
            }
            @Override
            public boolean isAutoClean() {
                return false;
            }
            @Override
            public List<UpdateField> getUpdateFields() {
                return updateFields.isEmpty() ? null : updateFields;
            }
            @Override
            public ManagedObject getManagedObject() {
                // TODO Auto-generated method stub
                return null;
            }};
    }
    
    public static String inferReductionKey(OmiTrapDef trapDef) {
        final StringBuilder reductionKeySb = new StringBuilder();
        reductionKeySb.append("%uei%:%dpname%:%nodeid%");
        for (String placeholderToken : extractPlaceholderTokens(trapDef.getText())) {
            reductionKeySb.append(":");
            reductionKeySb.append(placeholderToken);
        }
        return reductionKeySb.toString();
    }

    public static Severity toOnmsSeverity(String omiSeverity) {
        if (omiSeverity == null) {
            return Severity.INDETERMINATE;
        }
        return Severity.get(omiSeverity.toLowerCase());
    }
    
    public static String replacePolicyvarPlaceholderTokens(final String input) {
        if (input == null) {
            return null;
        }
        String output = input;
        final Matcher mat = PLACEHOLDER_PATTERN_POLICYVAR.matcher(input);
        StringBuffer replSb = new StringBuffer();
        StringBuilder workingSb = new StringBuilder();
        while (mat.find()) {
            workingSb = new StringBuilder();
            final String tokenName = mat.group(1);
            if (tokenName == null) {
                continue;
            }
            if (tokenName.matches("^\\d+$")) {
                // Returns one or more of the fifteen possible event parameters that are part of an SNMP event.
                // (<$1> returns the first variable, <$2> returns the second variable, and so on.) 
                workingSb.append("%parm[").append("#").append(tokenName).append("]%");
            } else if (tokenName.equals("*")) {
                // Returns all variables assigned to the event up to the possible fifteen
                workingSb.append("%parm[all]%");
            } else if (tokenName.equals("#")) {
                // Returns the number of variables in an enterprise-specific SNMP event
                workingSb.append("%parm[##]%");
            } else if (tokenName.equals("@")) {
                // Returns the time the event was received as the number of seconds since Jan 1, 1970 using the time_t representation
                LOG.warn("Policy variable <$@> is not directly translatable. Substituting a long textual UTC timestamp.");
                workingSb.append("%time%");
            } else if (tokenName.equals("A")) {
                // Returns the node that produced the event
                workingSb.append("%snmphost%");
            } else if (tokenName.equals("C")) {
                // Returns the community of the event
                workingSb.append("%community%");
            } else if (tokenName.equals("E")) {
                // Returns the enterprise ID of the event
                workingSb.append("%id%");
            } else if (tokenName.equals("e")) {
                // Returns the enterprise ID of the event
                workingSb.append("%id%");
            } else if (tokenName.equals("G")) {
                // Returns the generic event ID
                workingSb.append("%generic%");
            } else if (tokenName.equals("S")) {
                // Returns the specific event ID
                workingSb.append("%specific%");
            } else if (tokenName.equals("s")) {
                // Returns the event's severity
                workingSb.append("%severity%");
            } else if (tokenName.equals("T")) {
                // Returns the event time stamp
                workingSb.append("%time%");
            } else if (tokenName.equals("V")) {
                // Returns the event type, based on the transport from which the event was received. Currently supported types
                // are SNMPv1, SNMPv2, CMIP, GENERIC, and SNMPv2INFORM
                workingSb.append("SNMP%version%");
            } else if (tokenName.equals("X") || tokenName.equals("x")) {
                // Returns the time / date the event was received using the local time representation
                LOG.warn("Policy variables <$X> and <$x> are not directly translabable. Substituting a short UTC date+time.");
                workingSb.append("%shorttime%");
            } else if (tokenName.equals("MSG_TEXT")) {
                // Returns the full text of the event.
                workingSb.append("%logmsg%");
            } else if (tokenName.equals("MSG_ID")) {
                // Returns the unique identity number of the event.
                workingSb.append("%eventid%");
            } else if (tokenName.equals("MSG_NODE_NAME")) {
                // Returns the hostname of the node on which the original event took place (this is the hostname that the agent resolves for the node).
                workingSb.append("%interfaceresolve%");
            } else {
                LOG.warn("Policy variable <${}> has no translation. Leaving token intact as an event parameter expansion. Runtime result will be empty.", tokenName);
                workingSb.append("%parm[").append(tokenName).append("]%");
            }
            mat.appendReplacement(replSb, workingSb.toString());
        }
        mat.appendTail(replSb);
        return "".equals(replSb.toString()) ? output : replSb.toString();
    }
    
    public static String replaceUservarPlaceholderTokens(final String input) {
        if (input == null) {
            return null;
        }
        String output = input;
        final Matcher mat = PLACEHOLDER_PATTERN_USERVAR.matcher(input);
        StringBuffer replSb = new StringBuffer();
        while (mat.find()) {
            final String varName = mat.group(1);
            if (varName == null) {
                continue;
            }
            mat.appendReplacement(replSb, String.format("%%parm[%s]%%", adaptUserVarNameToRegex(varName)));
        }
        mat.appendTail(replSb);
        return "".equals(replSb.toString()) ? output : replSb.toString();
    }


    public static List<String> extractPlaceholderTokens(String string) {
        if (string == null) {
            return Collections.emptyList();
        }
        final List<String> tokens = new ArrayList<>();
        final Matcher m = PLACEHOLDER_PATTERN_POLICYVAR.matcher(string);
        while(m.find()) {
            tokens.add(String.format("%%parm[#%s]%%", m.group(1)));
        }
        return tokens;
    }
    
    public static String decorateOperInstruct(String input) {
        if (input == null || "".equals(input)) {
            return input;
        }
        String result = decorateEmailAddresses(input);
        result = decorateHttpLinks(result);
        result = decorateNewlines(result);
        return result;
    }
    
    public static String decorateEmailAddresses(String input) {
        if (input == null || "".equals(input)) {
            return input;
        }
        String result = input;
        Matcher m = BARE_EMAILADDR_PATTERN.matcher(input);
        if (m.find()) {
            result = m.replaceAll("$1<a href=\"mailto:$2\">$2</a>");
        }
        return result;
    }
    
    public static String decorateHttpLinks(String input) {
        if (input == null || "".equals(input)) {
            return input;
        }
        String result = input;
        Matcher m = BARE_HTTPLINK_PATTERN.matcher(input);
        if (m.find()) {
            result = m.replaceAll("$1<a target=\"_blank\" href=\"$2\">$2</a>$3");
        }
        return result;
    }
    
    public static String decorateNewlines(String input) {
        if (input == null) {
            return input;
        }
        return input.replace("\n", "<br/>");
    }
    
    public static boolean isGratuitouslyRegexedInteger(final String string) {
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
    
    public static boolean looksLiteral(final String string) {
        if (string == null) {
            return false;
        }
        if     (   ! string.startsWith("^")
                && ! string.endsWith("$")
                && ! string.contains("<")
                && ! string.contains(">")
                && ! string.contains("[")
                && ! string.contains("]")) {
            return true;
        }
        return false;
    }
    
    public static String translateOmiPatternToRegex(final String input) {
        String curVal = input, lastVal = input;
        // Attempt to replace pattern structures from the inside out

        // Start with non-quantified, non-uservar tokens such as <*>
        // Repeat until we reach stasis
        int i = 0;
        do {
            i++;
            lastVal = curVal;
            curVal = translateAllSimpleActionGroupsToRegex(lastVal);
            LOG.debug("SimpleActionGroups Pass {}: {} -> {}",i, lastVal.length(), curVal.length());
        } while (!curVal.equals(lastVal));
        
        // Next, replace complex action groups such as <4#.somevar>
        i = 0;
        do {
            i++;
            lastVal = curVal;
            curVal = translateAllComplexActionGroupsToRegex(lastVal);
            LOG.debug("ComplexActionGroups Pass {}: {} -> {}",i, lastVal.length(), curVal.length());
        } while (!curVal.equals(lastVal));
        
        // Now replace negated action patterns such as <![Warning]>
        // TODO: This one needs refinement
        i = 0;
        do {
            i++;
            lastVal = curVal;
            curVal = translateAllNegativeActionGroupsToRegex(lastVal);
            LOG.debug("NegativeActionGroups Pass {}: {} -> {}",i, lastVal.length(), curVal.length());
        } while (!curVal.equals(lastVal));
        
        // Separately handle assignment-only action groups such as <[foo|bar].thing>
        i = 0;
        do {
            i++;
            lastVal = curVal;
            curVal = translateAllAssignOnlyActionGroupsToRegex(lastVal);
            LOG.debug("AssignOnlyActionGroups Pass {}: {} -> {}",i, lastVal.length(), curVal.length());
        } while (!curVal.equals(lastVal));
        
        // Finally, sub in parens for squares, which do basically the same job
        i = 0;
        do {
            i++;
            lastVal = curVal;
            curVal = translateAllSquareBracketsToParens(lastVal);
            LOG.debug("SquareBrackets Pass {}: {} -> {}",i, lastVal.length(), curVal.length());
        } while (!curVal.equals(lastVal));
        
        return curVal;
    }
    
    public static String translateAllSimpleActionGroupsToRegex(final String input) {
        String output = input
        .replaceAll("(?<!\\{1})<\\*>", Matcher.quoteReplacement(TOKEN_ASTERISK_REGEX_EQUIVALENT+"*?"))        // <*> matches any string of zero or more arbitrary characters (including separators)
        .replaceAll("(?<!\\{1})<@>", Matcher.quoteReplacement(TOKEN_AT_REGEX_EQUIVALENT+"+?"))                // <@> matches any string that contains no separator characters, in other words, a sequence of one or more non-separators; this can be used for matching words
        .replaceAll("(?<!\\{1})<#>", Matcher.quoteReplacement(TOKEN_HASH_REGEX_EQUIVALENT+"+?"))              // <#> matches a sequence of one or more digits
        .replaceAll("(?<!\\{1})<_>", Matcher.quoteReplacement(TOKEN_UNDERSCORE_REGEX_EQUIVALENT+"+?"))        // <_> matches a sequence of one or more field separators
        .replaceAll("(?<!\\{1})</>", Matcher.quoteReplacement(TOKEN_SLASH_REGEX_EQUIVALENT+"+?"))             // </> matches one or more line breaks
        .replaceAll("(?<!\\{1})<S>", Matcher.quoteReplacement(TOKEN_S_REGEX_EQUIVALENT));                     // <S> matches one or more white space characters: space, tab and new line characters (" ", \t, \n, \r)
        return output;
    }
    
    public static String translateAllComplexActionGroupsToRegex(final String input) {
        String output = input;
        // If no <> remain, don't bother with replacing this stuff
        if (!output.contains("<") && !output.contains(">")) {
            return output;
        }
        Matcher mat = COMPLEX_ACTION_GROUP_PATTERN.matcher(output);
        StringBuffer replSb = new StringBuffer();
        StringBuilder workingSb = new StringBuilder();
        while (mat.find()) {
            LOG.debug("Replacing complex action-groups in range {}-{} ('{}')", mat.start(), mat.end(), input.substring(mat.start(), mat.end()));
            workingSb = new StringBuilder();
            final String quantifier = mat.group(1);
            final String globToken = mat.group(2);
            final String userVar = mat.group(3);
            
            if (userVar != null) {
                // Note that OMi user var names may contain some non-alphanumeric characters,
                // but regex named-capturing group names may not. Deal with this first.
                // Note also that userVar carries the leading dot, so we do substring(1) to drop it
                final String ncgName = adaptUserVarNameToRegex(userVar.substring(1));
                // This opens a named-capturing group, which we will close down below
                // e.g. "(?<stuff>" in case of "<*.stuff>"
                workingSb.append("(?<").append(ncgName).append(">");
            }
            switch(globToken) {
            case "*":
                // This appends the atomic regex equivalent of the glob-token, along with
                // the appropriate quantifier depending on whether the action group is quantified
                workingSb.append(Matcher.quoteReplacement(TOKEN_ASTERISK_REGEX_EQUIVALENT));
                if (quantifier != null) {
                    // e.g. "{4}" in case of "<4*>"
                    workingSb.append("{").append(quantifier).append("}");
                } else {
                    workingSb.append("*?");
                }
                break;
            case "@":
                workingSb.append(Matcher.quoteReplacement(TOKEN_AT_REGEX_EQUIVALENT));
                if (quantifier != null) {
                    workingSb.append("{").append(quantifier).append("}");
                } else {
                    workingSb.append("+?");
                }
                break;
            case "#":
                workingSb.append(Matcher.quoteReplacement(TOKEN_HASH_REGEX_EQUIVALENT));
                if (quantifier != null) {
                    workingSb.append("{").append(quantifier).append("}");
                } else {
                    workingSb.append("+?");
                }
                break;
            case "_":
                workingSb.append(Matcher.quoteReplacement(TOKEN_UNDERSCORE_REGEX_EQUIVALENT));
                if (quantifier != null) {
                    workingSb.append("{").append(quantifier).append("}");
                } else {
                    workingSb.append("+?");
                }
                break;
            case "/":
                workingSb.append(Matcher.quoteReplacement(TOKEN_SLASH_REGEX_EQUIVALENT));
                if (quantifier != null) {
                    workingSb.append("{").append(quantifier).append("}");
                } else {
                    workingSb.append("+");
                }
            case "S":
                workingSb.append(Matcher.quoteReplacement(TOKEN_S_REGEX_EQUIVALENT));
                if (quantifier != null) {
                    workingSb.append("{").append(quantifier).append("}");
                } else {
                    workingSb.append("+");
                }
            }
            if (userVar != null) {
                // Here is where we close the named-capturing group
                workingSb.append(")");
            }
            
            LOG.debug("Appending replacement '{}' for ComplexActionGroup range {}-{}", workingSb.toString(), mat.start(), mat.end());
            mat.appendReplacement(replSb, workingSb.toString());
        }
        mat.appendTail(replSb);
        return "".equals(replSb.toString()) ? output : replSb.toString();
    }
    
    public static String translateAllNegativeActionGroupsToRegex(final String input) {
        String output = input;
        if (!output.contains("<") && !output.contains(">")) {
            return output;
        }
        Matcher mat = NEGATED_ACTION_GROUP_PATTERN.matcher(output);
        StringBuffer replSb = new StringBuffer();
        StringBuilder workingSb = new StringBuilder();
        while (mat.find()) {
            LOG.debug("Replacing negative action-groups in range {}-{} ('{}')", mat.start(), mat.end(), input.substring(mat.start(), mat.end()));

            workingSb = new StringBuilder();
            final String negatedSubpattern = mat.group(1);
            // TODO: I might be using negative lookahead wrong here...
            workingSb.append("(?!").append(negatedSubpattern).append(")");

            LOG.debug("Appending replacement '{}' for NegativeActionGroup range {}-{}", workingSb.toString(), mat.start(), mat.end());
            mat.appendReplacement(replSb, workingSb.toString());
        }
        return "".equals(replSb.toString()) ? output : replSb.toString();
    }
    
    public static String translateAllAssignOnlyActionGroupsToRegex(final String input) {
        String output = input;
        if (!output.contains("<") && !output.contains(">")) {
            return output;
        }

        Matcher mat = ASSIGN_ONLY_ACTION_GROUP_PATTERN.matcher(output);
        StringBuffer replSb = new StringBuffer();
        StringBuilder workingSb = new StringBuilder();
        while (mat.find()) {
            LOG.debug("Replacing assign-only action-groups in range {}-{} ('{}')", mat.start(), mat.end(), input.substring(mat.start(), mat.end()));
            
            workingSb = new StringBuilder();
            final String groupBody = mat.group(1);
            final String userVar = mat.group(2);
            
            // Note that OMi user var names may contain some non-alphanumeric characters,
            // but regex named-capturing group names may not. Deal with this first.
            // Note also that userVar carries the leading dot, so we do substring(1) to drop it
            final String ncgName = adaptUserVarNameToRegex(userVar.substring(1));
            
            workingSb.append("(?<").append(ncgName).append(">").append(groupBody).append(")");

            LOG.debug("Appending replacement '{}' for AssignOnlyActionGroup range {}-{}", workingSb.toString(), mat.start(), mat.end());
            mat.appendReplacement(replSb, workingSb.toString());
        }
        mat.appendTail(replSb);
        return "".equals(replSb.toString()) ? output : replSb.toString();
    }
    
    public static String translateAllSquareBracketsToParens(final String input) {
        String output = input;
        if (!output.contains("[") && !output.contains("]")) {
            return output;
        }
        Matcher mat = INNER_GROUPING_PATTERN.matcher(output);
        StringBuffer replSb = new StringBuffer();
        while (mat.find()) {
            mat.appendReplacement(replSb, "($1)");
        }
        mat.appendTail(replSb);
        return "".equals(replSb.toString()) ? output : replSb.toString();
    }
    
    // Given the name of an OMi policy user variable (which may contain
    // underscores and dashes, at least), convert to a purely alphanumeric
    // name as required for use as a regex named-capturing group. We do this
    // by camel-casing.
    public static String adaptUserVarNameToRegex(final String input) {
        LOG.debug("adaptUserVarNameToRegex: Dealing with var name '{}'", input);
        if (input == null) {
            return null;
        }
        String output = input;
        if (input.matches("^[A-Za-z][A-Za-z0-9]+$")) {
            LOG.debug("adaptUserVarNameToRegex: var name {} does not require adaptation. Returning unmodified.", input);
            return output;
        }
        
        // First, upper-case any lower-case letters preceded by a non-alphanumeric
        Matcher mat = ALPHA_LC_CHARS_PRECEDED_BY_NON_ALPHANUM.matcher(input);
        StringBuffer replSb = new StringBuffer();
        while (mat.find()) {
            String successorChar = mat.group(1);
            LOG.debug("adaptUserVarNameToRegex: upper-casing char '{}' of var name '{}'", successorChar, input);
            mat.appendReplacement(replSb, successorChar.toUpperCase());
        }
        mat.appendTail(replSb);
        
        if (! "".equals(replSb.toString())) {
            output = replSb.toString();
        }

        // Then strain out any remaining non-alphanumerics
        return output.replaceAll("[^A-Za-z0-9]+", "");
    }
}
