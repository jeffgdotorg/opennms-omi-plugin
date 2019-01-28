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

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.antlr.v4.runtime.CharStream;
import org.antlr.v4.runtime.CharStreams;
import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.tree.ParseTree;
import org.opennms.plugins.omi.model.MyOMiPolicyVisitor;
import org.opennms.plugins.omi.model.OmiTrapDef;
import org.opennms.plugins.omi.policy.parser.OMiPolicyLexer;
import org.opennms.plugins.omi.policy.parser.OMiPolicyParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DefaultOmiDefinitionProvider implements OmiDefinitionProvider {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultOmiDefinitionProvider.class);

    private final File omPolicyRoot;
    private final List<OmiTrapDef> trapDefs = new LinkedList<>();

    public DefaultOmiDefinitionProvider(String omPolicyRoot) throws IOException {
        this(new File(Objects.requireNonNull(omPolicyRoot, "path to root is required")));
    }

    public DefaultOmiDefinitionProvider(File omPolicyRoot) throws IOException {
        Objects.requireNonNull(omPolicyRoot, "root is required");
        this.omPolicyRoot = omPolicyRoot;
        LOG.info("DefaultOmiDefinitionProvider initialized.");
        parsePolicyFiles();
    }

    private void parsePolicyFiles() throws IOException {
        final List<File> policyFiles = getPolicyFilesIn(omPolicyRoot);
        LOG.debug("Found {} policy files in {}: {}", policyFiles.size(), omPolicyRoot, policyFiles);

        // Parse the files
        for (File policyFile : policyFiles) {
            final OMiPolicyParser parser = parse(policyFile);
            ParseTree parseTree = parser.policy();
            MyOMiPolicyVisitor<Void> visitor = new MyOMiPolicyVisitor<>();
            visitor.visit(parseTree);
            trapDefs.addAll(visitor.getTrapDefs());
        }
        LOG.debug("Generated {} trap definitions.", trapDefs.size());
    }

    @Override
    public List<OmiTrapDef> getTrapDefs() {
        return trapDefs;
    }

    private static List<File> getPolicyFilesIn(File sourceFolder) {
        final String[] fileNames = sourceFolder.list((dir, name) -> name.toLowerCase().endsWith("_data"));
        if (fileNames != null) {
            return Arrays.stream(fileNames).map(f -> new File(sourceFolder, f)).collect(Collectors.toList());
        } else {
            return Collections.emptyList();
        }
    }

    private static OMiPolicyParser parse(File policyFile) throws IOException {
        CharStream cs = CharStreams.fromFileName(policyFile.getAbsolutePath(), StandardCharsets.UTF_8);
        OMiPolicyLexer lexer = new OMiPolicyLexer(cs);
        CommonTokenStream tokens = new CommonTokenStream(lexer);
        return new OMiPolicyParser(tokens);
    }
}
