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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.Matchers.startsWith;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.Objects;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.opennms.plugins.omi.model.OmiTrapDef;

import com.google.common.io.Resources;

public class OmiDefinitionProviderTest {

    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    @Test
    public void canProvideDefinitions() throws IOException {
        final File policyData = temporaryFolder.newFile("netapp_test_policy_data");
        try (InputStream is = Resources.getResource("netapp_test_policy_data").openStream()) {
            Files.copy(is, policyData.toPath(), StandardCopyOption.REPLACE_EXISTING);
        }

        OmiDefinitionProvider omiDefProvider = new DefaultOmiDefinitionProvider(temporaryFolder.getRoot());
        final List<OmiTrapDef> trapDefs = omiDefProvider.getTrapDefs();

        // Make sure we have at least 1
        assertThat(trapDefs, hasSize(greaterThanOrEqualTo(1)));

        // Look for a specific entry
        OmiTrapDef trapDef = findTrap(trapDefs, ".1.3.6.1.4.1.789", 3, null);
        assertThat(trapDef, notNullValue());
        assertThat(trapDef.getLabel(), equalTo("NetApp_Link_Up"));
        assertThat(trapDef.getSeverity(), equalTo("Normal"));
        assertThat(trapDef.getText(), equalTo("Link <$1> up."));
        assertThat(trapDef.getApplication(), equalTo("NetApp"));
        assertThat(trapDef.getMsgGrp(), equalTo("Storage"));
        assertThat(trapDef.getHelpText(), startsWith("EVENT NAME: NetApp_Link_Up"));

        // Look for another specific entry
        trapDef = findTrap(trapDefs, ".1.3.6.1.4.1.789", 2, null);
        assertThat(trapDef, notNullValue());
        assertThat(trapDef.getLabel(), equalTo("NetApp_Link_Down"));
        assertThat(trapDef.getSeverity(), equalTo("Major"));
        assertThat(trapDef.getText(), equalTo("Link <$1> down."));
        assertThat(trapDef.getApplication(), equalTo("NetApp"));
        assertThat(trapDef.getMsgGrp(), equalTo("Storage"));
        assertThat(trapDef.getHelpText(), startsWith("EVENT NAME: NetApp_Link_Down"));
    }

    private static OmiTrapDef findTrap(List<OmiTrapDef> trapDefs, String enterpriseId, Integer generic, Integer specific) {
        return trapDefs.stream().filter(t -> Objects.equals(t.getEnterpriseId(), enterpriseId) &&
                Objects.equals(t.getGeneric(), generic) &&
                Objects.equals(t.getSpecific(), specific)).findAny().orElse(null);
    }
}
