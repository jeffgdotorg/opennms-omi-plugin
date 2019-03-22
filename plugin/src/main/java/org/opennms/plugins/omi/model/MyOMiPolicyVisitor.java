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

import org.antlr.v4.runtime.ParserRuleContext;
import org.antlr.v4.runtime.tree.ParseTree;
import org.jline.utils.Log;
import org.opennms.plugins.omi.policy.parser.OMiPolicyBaseVisitor;
import org.opennms.plugins.omi.policy.parser.OMiPolicyParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MyOMiPolicyVisitor<T> extends OMiPolicyBaseVisitor<T> {
    private List<OmiTrapDef> trapDefs = new LinkedList<>();
    private OmiTrapDef trapDef = new OmiTrapDef();
    
    private String defaultSourceName;
    private String defaultLabel;
    private String defaultSeverity;
    private String defaultApplication;
    private String defaultMsgGrp;
    private String defaultObject;
    private boolean defaultUnmatchedLogOnly = false;
    private MatchType curMatchType;
    
    private final Pattern varbindPattern = Pattern.compile("^\\$(\\d{1,2})$");
    
    private static final Logger LOG = LoggerFactory.getLogger(MyOMiPolicyVisitor.class);

    @Override
    public T visitCondition_description(OMiPolicyParser.Condition_descriptionContext ctx) {
        ParseTree lastChild = null;
        for (ParseTree child : ctx.children) {
            if (lastChild != null) {
                if ("DESCRIPTION".equals(lastChild.getText())) {
                    trapDef.setLabel(unescapeQuotes(stripQuotes(child.getText())));
                }
            }
            lastChild = child;
        }
        
//        LOG.debug("Visiting children of this {}, which is a child of a {}", ctx.getClass().getSimpleName(), ctx.getParent().getClass().getSimpleName());
        return visitChildren(ctx);
    }

    @Override
    public T visitSnmpsupp_unm_conds(OMiPolicyParser.Snmpsupp_unm_condsContext ctx) {
        curMatchType = MatchType.SUPP_UNMATCH;
        return visitChildren(ctx);
    }
    
    @Override
    public T visitSnmpsuppressconds(OMiPolicyParser.SnmpsuppresscondsContext ctx) {
        curMatchType = MatchType.SUPP_MATCH;
        ParseTree lastChild = null;
        for (ParseTree child : ctx.children) {
            if (lastChild != null) {
                if ("DESCRIPTION".equals(lastChild.getText())) {
                    trapDef.setLabel(unescapeQuotes(stripQuotes(child.getText())));
                }
            }
            lastChild = child;
        }
        
//        LOG.debug("Visiting children of this {}, which is a child of a {}", ctx.getClass().getSimpleName(), ctx.getParent().getClass().getSimpleName());
        return visitChildren(ctx);
    }

    @Override
    public T visitSnmpmsgconds(OMiPolicyParser.SnmpmsgcondsContext ctx) {
        curMatchType = MatchType.MSG_MATCH;
        ParseTree lastChild = null;
        for (ParseTree child : ctx.children) {
            if (lastChild != null) {
                if ("DESCRIPTION".equals(lastChild.getText())) {
                    trapDef.setLabel(unescapeQuotes(stripQuotes(child.getText())));
                }
            }
            lastChild = child;
        }

//        LOG.debug("Visiting children of this {}, which is a child of a {}", ctx.getClass().getSimpleName(), ctx.getParent().getClass().getSimpleName());
        return visitChildren(ctx);
    }

    @Override
    public T visitSnmpconds(OMiPolicyParser.SnmpcondsContext ctx) {
        ParseTree lastChild = null;
        for (ParseTree child : ctx.children) {
            if (lastChild != null) {
                if ("$e".equals(lastChild.getText())) {
                    trapDef.setEnterpriseId(stripQuotes(child.getText()));
                }
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
        if (ctx.getParent() instanceof OMiPolicyParser.SnmpsuppresscondsContext && lastChild.equals(ctx.getChild(ctx.getChildCount() - 1))) {
            pushTrapDef();
        }
        
//        LOG.debug("Visiting children of this {}, which is a child of a {}", ctx.getClass().getSimpleName(), ctx.getParent().getClass().getSimpleName());
        return visitChildren(ctx);
    }

    @Override
    public T visitSet(OMiPolicyParser.SetContext ctx) {
        ParseTree lastChild = null;
        boolean inMsgKeyRelation = false;
        for (ParseTree child : ctx.children) {
            if (lastChild != null) {
                if ("HELPTEXT".equals(lastChild.getText())) {
                    String helpText = child.getText();
                    trapDef.setHelpText(unescapeQuotes(stripQuotes(helpText)));
                }
                if ("SEVERITY".equals(lastChild.getText())) {
                    String severity = child.getText();
                    trapDef.setSeverity(severity);
                }
                if ("TEXT".equals(lastChild.getText())) {
                    String text = child.getText();
                    trapDef.setText(unescapeQuotes(stripQuotes(text)));
                }
                if ("APPLICATION".equals(lastChild.getText())) {
                    String application = child.getText();
                    trapDef.setApplication(stripQuotes(application));
                }
                if ("MSGGRP".equals(lastChild.getText())) {
                    String msgGrp = child.getText();
                    trapDef.setMsgGrp(stripQuotes(msgGrp));
                }
                if ("OBJECT".equals(lastChild.getText())) {
                    trapDef.setObject(stripQuotes(child.getText()));
                }
                if ("SERVERLOGONLY".equals(lastChild.getText())) {
                    trapDef.setServerLogOnly(true);
                }
                if ("MSGKEY".equals(lastChild.getText())) {
                    trapDef.setMsgKey(stripQuotes(child.getText()));
                }
                if ("MSGKEYRELATION".equals(lastChild.getText())) {
                    inMsgKeyRelation = true;
                }
                if (inMsgKeyRelation && "ACK".equals(lastChild.getText())) {
                    trapDef.setMsgKeyRelation(stripQuotes(child.getText()));
                    inMsgKeyRelation = false;
                }
            }
            lastChild = child;
        }
        if (ctx.equals(ctx.getParent().getChild(ctx.getParent().getChildCount() - 1))) {
            pushTrapDef();
        }
        
//        LOG.debug("Visiting children of this {}, which is a child of a {}", ctx.getClass().getSimpleName(), ctx.getParent().getClass().getSimpleName());
        return visitChildren(ctx);
    }


    @Override
    public T visitSnmpsource(OMiPolicyParser.SnmpsourceContext ctx) {
        ParseTree lastChild = null;
        for (ParseTree child : ctx.children) {
            if (lastChild != null) {
//                LOG.debug("In an snmpsource, visiting tuple '{}' '{}'", lastChild.getText(), child.getText());
                if ("SNMP".equals(lastChild.getText())) {
                    defaultSourceName = stripQuotes(child.getText());
                }
                if ("DESCRIPTION".equals(lastChild.getText())) {
                    defaultLabel = unescapeQuotes(stripQuotes(child.getText()));
                }
                if ("SEVERITY".equals(lastChild.getText())) {
                    defaultSeverity = nullSafeTrim(child.getText());
                }
                if ("APPLICATION".equals(lastChild.getText())) {
                    defaultApplication = stripQuotes(child.getText());
                }
                if ("MSGGRP".equals(lastChild.getText())) {
                    defaultMsgGrp = stripQuotes(child.getText());
                }
            }
            lastChild = child;
        }
        
//        LOG.debug("Visiting children of this {}, which is a child of a {}", ctx.getClass().getSimpleName(), ctx.getParent().getClass().getSimpleName());
        return visitChildren(ctx);
    }
    
    @Override
    public T visitStddefault(OMiPolicyParser.StddefaultContext ctx) {
        ParseTree lastChild = null;
        for (ParseTree child : ctx.children) {
            if (lastChild != null) {
                if ("DESCRIPTION".equals(lastChild.getText())) {
                    defaultLabel = unescapeQuotes(stripQuotes(child.getText()));
                }
                if ("SEVERITY".equals(lastChild.getText())) {
                    defaultSeverity = nullSafeTrim(child.getText());
                }
                if ("APPLICATION".equals(lastChild.getText())) {
                    defaultApplication = stripQuotes(child.getText());
                }
                if ("MSGGRP".equals(lastChild.getText())) {
                    defaultMsgGrp = stripQuotes(child.getText());
                }
                if ("OBJECT".equals(lastChild.getText())) {
                    defaultObject = stripQuotes(child.getText());
                }

//                LOG.debug("In a stddefault, visiting tuple '{}' '{}'", lastChild.getText(), child.getText());
            }
            lastChild = child;
        }
        
//        LOG.debug("Visiting children of this {}, which is a child of a {}", ctx.getClass().getSimpleName(), ctx.getParent().getClass().getSimpleName());
        return visitChildren(ctx);
    }
    
    @Override
    public T visitCommonsourceoption(OMiPolicyParser.CommonsourceoptionContext ctx) {
        for (ParseTree child : ctx.children) {
            if ("UNMATCHEDLOGONLY".equals(child.getText()) ) {
                defaultUnmatchedLogOnly = true;
            }
//            LOG.debug("In a commonsourceoptions, visiting token '{}'", child.getText());
        }
        return visitChildren(ctx);
    }

    private void pushTrapDef() {
        fillDefaultTrapFields(trapDef);
        trapDefs.add(trapDef);
        LOG.debug("Pushed OmiTrapDef {}", trapDef.toString());
        trapDef = new OmiTrapDef();
    }

    public List<OmiTrapDef> getTrapDefs() {
        return trapDefs;
    }

    private static String stripQuotes(String text) {
        if (text == null) {
            return null;
        }
        String wip = nullSafeTrim(text);
        if (wip.startsWith("\"")) {
            wip = wip.substring(1);
        }
        if (wip.endsWith("\"")) {
            wip = wip.substring(0, wip.length() - 1);
        }
        return nullSafeTrim(wip);
    }

    private static String nullSafeTrim(String text) {
        if (text == null) {
            return null;
        }
        return text.trim();
    }
    
    private static String unescapeQuotes(String text) {
        if (text == null) {
            return null;
        }
        text = text.replace("\\\"", "\"");
        return text;
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
    
    private void fillDefaultTrapFields(OmiTrapDef trapDef) {
        if (trapDef.getLabel() == null) {
            trapDef.setLabel(defaultLabel);
        }
        if (trapDef.getApplication() == null) {
            trapDef.setApplication(defaultApplication);
        }
        if (trapDef.getMsgGrp() == null) {
            trapDef.setMsgGrp(defaultMsgGrp);
        }
        if (trapDef.getObject() == null) {
            trapDef.setObject(defaultObject);
        }
        if (trapDef.getSeverity() == null) {
            trapDef.setSeverity(defaultSeverity);
        }
        if (trapDef.getMatchType() == null) {
            trapDef.setMatchType(curMatchType);
        }
    }
}