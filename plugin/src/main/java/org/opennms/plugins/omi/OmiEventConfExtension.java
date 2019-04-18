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

    private static final Pattern PLACEHOLDER_PATTERN = Pattern.compile("<\\$(\\d+)>");
    
    private static final Pattern BARE_EMAILADDR_PATTERN = Pattern.compile("([^>:])([^,@ ]+@[^,@ \n]+)\\b");
    
    private static final Pattern BARE_HTTPLINK_PATTERN = Pattern.compile("([^\">])(https?://.*?)([ \n]|$)");
    
    private static final String TOKEN_ASTERISK_REGEX_EQUIVALENT = ".";
    private static final String TOKEN_AT_REGEX_EQUIVALENT = "\\w";
    private static final String TOKEN_HASH_REGEX_EQUIVALENT = "\\d";
    private static final String TOKEN_UNDERSCORE_REGEX_EQUIVALENT = "[_/\\:-]";
    private static final String TOKEN_SLASH_REGEX_EQUIVALENT = "[\\n\\r]";
    private static final String TOKEN_S_REGEX_EQUIVALENT = "[ \\t\\n\\r]";

    private static final Pattern NEGATED_ACTION_GROUP_PATTERN = Pattern.compile("(?<!\\{1})<!(\\[[^\\]]+\\])>");
    private static final Pattern COMPLEX_ACTION_GROUP_PATTERN = Pattern.compile("(?<!\\{1})<(\\d+)([*@#_/S])(\\.[A-Za-z][A-Za-z0-9_-]+)>");
    private static final Pattern INNER_GROUPING_PATTERN = Pattern.compile("(?<!\\{1})\\[([^\\]]+)(?<!\\{1})\\]");

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
                        String vbString;
                        final List<String> vbValues = new ArrayList<>();
                        for (String inValue : dtoVb.getValueExpressions()) {
                            if (isGratuitouslyRegexedInteger(inValue)) {
                                vbString = inValue.substring(1, inValue.length() - 1);
                                LOG.debug("Varbind #{} constraint value '{}' is a gratuitously-anchored integer value. Extracting and using sans regex in eventconf vbvalue: '{}'.", dtoVb.getVbOrdinal(), inValue, vbString);
                            } else {
                                vbString = translateOmiPatternToRegex(inValue);
                                LOG.debug("Translated OMi pattern '{}' to regex '{}'", inValue, vbString);
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
        final AlarmType alarmType = AlarmType.PROBLEM_WITHOUT_RESOLUTION;
        List<UpdateField> updateFields = new ArrayList<>();
        if (trapDef.getMsgKey() != null) {
            reductionKey = replacePlaceholderTokens(trapDef.getMsgKey());
        } else {
            reductionKey = inferReductionKey(trapDef);
        }
        
        if (trapDef.getMsgKeyRelation() != null) {
            clearKey = replacePlaceholderTokens(trapDef.getMsgKeyRelation());
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
        
        return new AlarmData() {

            @Override
            public String getReductionKey() {
                return reductionKey;
            }
            @Override
            public AlarmType getType() {
                return alarmType;
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
            LOG.debug("SimpleActionGroups Pass {}: '{}' -> '{}'",i, lastVal, curVal);
        } while (!curVal.equals(lastVal));
        
        // Next, replace complex action groups such as <4#.somevar>
        i = 0;
        do {
            i++;
            lastVal = curVal;
            curVal = translateAllComplexActionGroupsToRegex(lastVal);
            LOG.debug("ComplexActionGroups Pass {}: '{}' -> '{}'",i, lastVal, curVal);
        } while (!curVal.equals(lastVal));
        
        // Now replace negated action patterns such as <![Warning]>
        // TODO: This one needs refinement
        i = 0;
        do {
            i++;
            lastVal = curVal;
            curVal = translateAllNegativeActionGroupsToRegex(lastVal);
            LOG.debug("NegativeActionGroups Pass {}: '{}' -> '{}'",i, lastVal, curVal);
        } while (!curVal.equals(lastVal));
        
        // Finally, sub in parens for squares, which do basically the same job
        i = 0;
        do {
            i++;
            lastVal = curVal;
            curVal = translateAllSquareBracketsToParens(lastVal);
            LOG.debug("SquareBrackets Pass {}: '{}' -> '{}'",i, lastVal, curVal);
        } while (!curVal.equals(lastVal));
        
        return curVal;
    }
    
    public static String translateAllSimpleActionGroupsToRegex(final String input) {
        String output = input;
        output.replaceAll("(?<!\\{1})<\\*>", Matcher.quoteReplacement(TOKEN_ASTERISK_REGEX_EQUIVALENT+"*?"));        // <*> matches any string of zero or more arbitrary characters (including separators)
        output.replaceAll("(?<!\\{1})<@>", Matcher.quoteReplacement(TOKEN_AT_REGEX_EQUIVALENT+"+?"));                // <@> matches any string that contains no separator characters, in other words, a sequence of one or more non-separators; this can be used for matching words
        output.replaceAll("(?<!\\{1})<#>", Matcher.quoteReplacement(TOKEN_HASH_REGEX_EQUIVALENT+"+?"));              // <#> matches a sequence of one or more digits
        output.replaceAll("(?<!\\{1})<_>", Matcher.quoteReplacement(TOKEN_UNDERSCORE_REGEX_EQUIVALENT+"+?"));        // <_> matches a sequence of one or more field separators
        output.replaceAll("(?<!\\{1})</>", Matcher.quoteReplacement(TOKEN_SLASH_REGEX_EQUIVALENT+"+?"));             // </> matches one or more line breaks
        output.replaceAll("(?<!\\{1})<S>", Matcher.quoteReplacement(TOKEN_S_REGEX_EQUIVALENT));                      // <S> matches one or more white space characters: space, tab and new line characters (" ", \t, \n, \r)
        return output;
    }
    
    public static String translateAllComplexActionGroupsToRegex(final String input) {
        String output = input;
        // If no <> remain, don't bother with replacing this stuff
        if (!output.contains("<") && !output.contains(">")) {
            return output;
        }
        Matcher mat = COMPLEX_ACTION_GROUP_PATTERN.matcher(output);
        StringBuffer sb = new StringBuffer();
        while (mat.find()) {
            final String quantifier = mat.group(1);
            final String globToken = mat.group(2);
            final String userVar = mat.group(3);
            
            if (userVar != null) {
                mat.appendReplacement(sb, "(?<$3>");
            }
            switch(globToken) {
            case "*":
                mat.appendReplacement(sb, TOKEN_ASTERISK_REGEX_EQUIVALENT);
                if (quantifier != null) {
                    mat.appendReplacement(sb, "{$1}");
                } else {
                    mat.appendReplacement(sb, "*?");
                }
                break;
            case "@":
                mat.appendReplacement(sb, TOKEN_AT_REGEX_EQUIVALENT);
                if (quantifier != null) {
                    mat.appendReplacement(sb, "{$1}");
                } else {
                    mat.appendReplacement(sb, "+?");
                }
                break;
            case "#":
                mat.appendReplacement(sb, TOKEN_HASH_REGEX_EQUIVALENT);
                if (quantifier != null) {
                    mat.appendReplacement(sb, "{$1}");
                } else {
                    mat.appendReplacement(sb, "+?");
                }
                break;
            case "_":
                mat.appendReplacement(sb, TOKEN_UNDERSCORE_REGEX_EQUIVALENT);
                if (quantifier != null) {
                    mat.appendReplacement(sb, "{$1}");
                } else {
                    mat.appendReplacement(sb, "+?");
                }
                break;
            case "/":
                mat.appendReplacement(sb, TOKEN_SLASH_REGEX_EQUIVALENT);
                if (quantifier != null) {
                    mat.appendReplacement(sb, "{$1}");
                } else {
                    mat.appendReplacement(sb, "+");
                }
            case "S":
                mat.appendReplacement(sb, TOKEN_S_REGEX_EQUIVALENT);
                if (quantifier != null) {
                    mat.appendReplacement(sb, "{$1}");
                }
            }
            if (userVar != null) {
                mat.appendReplacement(sb, ")");
            } else {
                mat.appendReplacement(sb, "+");
            }
        }
        mat.appendTail(sb);
        return sb.toString();
    }
    
    public static String translateAllNegativeActionGroupsToRegex(final String input) {
        String output = input;
        if (!output.contains("<") && !output.contains(">")) {
            return output;
        }
        Matcher mat = NEGATED_ACTION_GROUP_PATTERN.matcher(output);
        StringBuffer sb = new StringBuffer();
        while (mat.find()) {
            final String negatedSubpattern = mat.group(1);
            // TODO: I might be using negative lookahead wrong here...
            mat.appendReplacement(sb, "(?!$1)");
        }
        return output;
    }
    
    public static String translateAllSquareBracketsToParens(final String input) {
        String output = input;
        if (!output.contains("[") && !output.contains("]")) {
            return output;
        }
        Matcher mat = INNER_GROUPING_PATTERN.matcher(output);
        StringBuffer sb = new StringBuffer();
        while (mat.find()) {
            mat.appendReplacement(sb, "(?:$1)");
        }
        return output;
    }
}
