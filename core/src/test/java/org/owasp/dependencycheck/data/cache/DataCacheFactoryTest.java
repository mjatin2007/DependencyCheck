/*
 * This file is part of dependency-check-core.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2019 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.cache;

import org.apache.commons.jcs3.JCS;
import org.apache.commons.jcs3.access.CacheAccess;
import org.apache.commons.jcs3.engine.behavior.ICompositeCacheAttributes;
import org.apache.commons.jcs3.engine.behavior.IElementAttributes;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.data.nexus.MavenArtifact;

import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 *
 * @author Jeremy Long
 */
class DataCacheFactoryTest extends BaseTest {

    /**
     * Test of getCache method, of class DataCacheFactory.
     */
    @Test
    void testGetCache() throws IOException {
        DataCacheFactory instance = new DataCacheFactory(getSettings());
        DataCache<List<MavenArtifact>> result = instance.getCentralCache();
        assertNotNull(result);

        File f = new File(getSettings().getDataDirectory(), "cache");
        assertTrue(f.isDirectory());

        FilenameFilter filter = (File f1, String name) -> name.startsWith("CENTRAL");
        assertTrue(f.listFiles(filter).length > 0);
    }

    @Test
    void testConfiguredAttributesForAllFactoryCaches() throws IOException {
        DataCacheFactory instance = new DataCacheFactory(getSettings());
        assertNotNull(instance.getNodeAuditCache());
        assertNotNull(instance.getCentralCache());
        assertNotNull(instance.getPomCache());

        assertRegionAttributes("NODEAUDIT", 86400L);
        assertRegionAttributes("CENTRAL", 2592000L);
        assertRegionAttributes("POM", 7776000L);
    }

    private static void assertRegionAttributes(String region, long maxLife) throws IOException {
        CacheAccess<Object, Object> cache = JCS.getInstance(region);
        IElementAttributes elementAttributes = cache.getDefaultElementAttributes();
        ICompositeCacheAttributes cacheAttributes = cache.getCacheAttributes();
        assertFalse(elementAttributes.getIsEternal(), region + " should expire entries");
        assertEquals(maxLife, elementAttributes.getMaxLife(), region + " MaxLife");
        assertEquals(0, cacheAttributes.getMaxObjects(), region + " MaxObjects");
        assertEquals(ICompositeCacheAttributes.DiskUsagePattern.UPDATE,
                cacheAttributes.getDiskUsagePattern(), region + " disk usage pattern");
        assertTrue(cacheAttributes.isUseDisk(), region + " should use disk");
    }

}
