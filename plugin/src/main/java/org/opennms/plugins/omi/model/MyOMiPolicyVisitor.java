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

import java.util.LinkedList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.antlr.v4.runtime.tree.ParseTree;
import org.jline.utils.Log;
import org.opennms.plugins.omi.policy.parser.OMiPolicyBaseVisitor;
import org.opennms.plugins.omi.policy.parser.OMiPolicyParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MyOMiPolicyVisitor<T> extends OMiPolicyBaseVisitor<T> {
    private List<OmiTrapDef> trapDefs = new LinkedList<>();
    private OmiTrapDef trapDef = new OmiTrapDef();
    
    private String curSourceLabel;
    private String curSeverity;
    private String curApplication;
    private String curMsgGrp;
    private String curObject;
    private MatchType curMatchType;
    
    private final Pattern varbindPattern = Pattern.compile("^\\$([0-9]|1[0-5])$");
    
    private static final Logger LOG = LoggerFactory.getLogger(MyOMiPolicyVisitor.class);

    @Override
    public T visitCondition_description(OMiPolicyParser.Condition_descriptionContext ctx) {
        trapDef.setLabel(stripQuotes(ctx.children.get(1).getText()));
        return visitChildren(ctx);
    }

    @Override
    public T visitSnmpmsgconds(OMiPolicyParser.SnmpmsgcondsContext ctx) {
        ParseTree lastChild = null;
        trapDef.setMatchType(MatchType.MSG_MATCH);
        for (ParseTree child : ctx.children) {
            if (lastChild != null) {
                if ("DESCRIPTION".equals(lastChild.getText())) {
                    trapDef.setLabel(nullSafeTrim(child.getText()));
                }
            }
            lastChild = child;
        }

        return visitChildren(ctx);
    }

    @Override
    public T visitSnmpconds(OMiPolicyParser.SnmpcondsContext ctx) {
        // Enterprise IDs are stored are string literals
        for (OMiPolicyParser.StringLiteralContext stringLiteral : ctx.stringLiteral()) {
            final String stringValue = stringLiteral.STRING_LITERAL().getText();
            trapDef.setEnterpriseId(stripQuotes(stringValue));
            break;
        }

        // Generics and specifics are stored as integers, we need to walk through the
        // children
        // to associate the ints with the previous child which contains the specifier
        // type (i.e. $G vs $S)
        ParseTree lastChild = null;
        for (ParseTree child : ctx.children) {
            if (lastChild != null) {
                if ("$G".equals(lastChild.getText())) {
                    trapDef.setGeneric(Integer.parseInt(child.getText()));
                }
                if ("$S".equals(lastChild.getText())) {
                    trapDef.setSpecific(Integer.parseInt(child.getText()));
                }
                Matcher vbMatcher = varbindPattern.matcher(lastChild.getText());
                if (vbMatcher.matches()) {
                    int vbNumber = Integer.valueOf(vbMatcher.group(1));
                    trapDef.addVarbindConstraint(new VarbindConstraint(vbNumber, stripQuotes(child.getText())));
                }
            }
            lastChild = child;
        }

        return visitChildren(ctx);
    }

    @Override
    public T visitSet(OMiPolicyParser.SetContext ctx) {
        ParseTree lastChild = null;
        for (ParseTree child : ctx.children) {
            if (lastChild != null) {
                if ("HELPTEXT".equals(lastChild.getText())) {
                    String helpText = child.getText();
                    trapDef.setHelpText(stripQuotes(helpText));
                    // TODO does this belong elsewhere? Can we count on HELPTEXT always being the last child of a SET?
                    pushTrapDef();
                }
                if ("SEVERITY".equals(lastChild.getText())) {
                    String severity = child.getText();
                    trapDef.setSeverity(severity);
                }
                if ("TEXT".equals(lastChild.getText())) {
                    String text = child.getText();
                    trapDef.setText(stripQuotes(text));
                }
                if ("APPLICATION".equals(lastChild.getText())) {
                    String application = child.getText();
                    trapDef.setApplication(stripQuotes(application));
                }
                if ("MSGGRP".equals(lastChild.getText())) {
                    String msgGrp = child.getText();
                    trapDef.setMsgGrp(stripQuotes(msgGrp));
                }
            }
            lastChild = child;
        }
        return visitChildren(ctx);
    }

    private void pushTrapDef() {
        trapDefs.add(trapDef);
        trapDef = new OmiTrapDef();
    }

    public List<OmiTrapDef> getTrapDefs() {
        return trapDefs;
    }

    private static String stripQuotes(String text) {
        // TODO: This could break if the string contains inner quotes that are escaped -
        // but we'll worry about that
        // when it does
        if (text == null) {
            return null;
        }
        return nullSafeTrim(text.replaceAll("\"", ""));
    }

    private static String nullSafeTrim(String text) {
        if (text == null) {
            return null;
        }
        return text.trim();
    }

    // DEBUGGING

    @Override
    public T visitSnmpsource(OMiPolicyParser.SnmpsourceContext ctx) {
        return visitChildren(ctx);
    }

    @Override
    public T visitSnmpdefopts(OMiPolicyParser.SnmpdefoptsContext ctx) {
        // System.out.println(ctx.getRuleIndex());
        return visitChildren(ctx);
    }

    @Override
    public T visitMsgconds(OMiPolicyParser.MsgcondsContext ctx) {
        // System.out.println("MSG COND: " + ctx.conds());
        return visitChildren(ctx);
    }

    @Override
    public T visitConds(OMiPolicyParser.CondsContext ctx) {
        // System.out.println("CONDS: " + ctx.pattern());
        return visitChildren(ctx);
    }

    @Override
    public T visitPattern(OMiPolicyParser.PatternContext ctx) {
        // System.out.println("PATTERNS: " + ctx);
        return visitChildren(ctx);
    }

    @Override
    public T visitCondition_id(OMiPolicyParser.Condition_idContext ctx) {
        // System.out.println("Condition ID: " +
        // ctx.stringLiteral().STRING_LITERAL().getText());
        return visitChildren(ctx);
    }

    @Override
    public T visitConditions(OMiPolicyParser.ConditionsContext ctx) {
        return visitChildren(ctx);
    }
}