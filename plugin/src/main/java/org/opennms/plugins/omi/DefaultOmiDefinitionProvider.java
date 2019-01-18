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
import java.util.List;

import org.antlr.v4.runtime.CharStream;
import org.antlr.v4.runtime.CharStreams;
import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.Lexer;
import org.antlr.v4.runtime.TokenStream;

import org.opennms.plugins.omi.model.OmiTrapDef;
import org.opennms.plugins.omi.policy.parser.OMiPolicyLexer;
import org.opennms.plugins.omi.policy.parser.OMiPolicyParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DefaultOmiDefinitionProvider implements OmiDefinitionProvider {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultOmiDefinitionProvider.class);

    public DefaultOmiDefinitionProvider() {
        // This line is here just to validate that we can load antlr and our
    	// parser in OSGi. It can be removed once we actually start using it
    	LOG.trace("Constant from antlr: {}", CharStream.EOF);
    	LOG.trace("Constant from our parser: {}", OMiPolicyParser.CHAR);
        LOG.info("DefaultOmiDefinitionProvider initialized.");
    }

    @Override
    public List<OmiTrapDef> getTrapDefs() {
        // TODO: Parse definitions and build trap defs
        final OmiTrapDef trapDef = new OmiTrapDef();
        trapDef.setLabel("my trap");
        trapDef.setTrapTypeOid(".1.3.6.1.4.1.99.98.9999.2.0.5");
        return Arrays.asList(trapDef);
    }
}
