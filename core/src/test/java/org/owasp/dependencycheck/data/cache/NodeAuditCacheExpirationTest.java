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
 * Copyright (c) 2026 Jatin Mannepalli. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.cache;

import org.apache.commons.jcs3.access.CacheAccess;
import org.apache.commons.jcs3.engine.behavior.IElementAttributes;
import org.apache.commons.jcs3.engine.control.CompositeCache;
import org.apache.commons.jcs3.engine.control.CompositeCacheManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Isolated;
import org.owasp.dependencycheck.data.nodeaudit.Advisory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Tests the effective expiration behavior of the Node Audit cache.
 */
@Isolated
class NodeAuditCacheExpirationTest {

    private static final String CACHE_PROPERTIES = "dependencycheck-cache.properties";
    private static final long EXPIRATION_TIMEOUT_NANOS = TimeUnit.SECONDS.toNanos(5);
    private static final long POLL_INTERVAL_MILLIS = 50;

    @TempDir
    Path tempDirectory;

    /**
     * Verifies that a newly written Node Audit entry honors the region's
     * configured maximum lifetime. The test shortens the lifetime to one second
     * while retaining the production configuration shape. It does not exercise
     * entries persisted under an earlier configuration.
     *
     * @throws IOException when the production cache configuration cannot be loaded
     * @throws InterruptedException when interrupted while waiting for expiration
     */
    @Test
    void testNodeAuditCacheExpiresAfterMaxLife() throws IOException, InterruptedException {
        Properties properties = loadCacheProperties();
        assertEquals("86400", properties.getProperty("jcs.region.NODEAUDIT.elementattributes.MaxLife"));
        properties.setProperty("jcs.region.NODEAUDIT.elementattributes.MaxLife", "1");
        retainNodeAuditRegion(properties);
        properties.setProperty("jcs.auxiliary.ODC.attributes.DiskPath",
                tempDirectory.resolve("NODEAUDIT").toAbsolutePath().toString());

        try (ScopedCacheManager manager = new ScopedCacheManager(properties)) {
            CompositeCache<String, List<Advisory>> compositeCache = manager.getCache("NODEAUDIT");
            CacheAccess<String, List<Advisory>> rawCache = new CacheAccess<>(compositeCache);
            DataCache<List<Advisory>> nodeAuditCache = new DataCache<>(rawCache);
            IElementAttributes attributes = compositeCache.getElementAttributes();
            String key = "expiration-characterization-" + System.nanoTime();

            try {
                nodeAuditCache.put(key, new ArrayList<>());
                assertNotNull(nodeAuditCache.get(key));
                List<Advisory> valueAfterExpiration = pollUntilExpired(nodeAuditCache, key);

                assertAll(
                        () -> assertFalse(attributes.getIsEternal(),
                                "NODEAUDIT must not be eternal when MaxLife is configured"),
                        () -> assertEquals(1, attributes.getMaxLife()),
                        () -> assertNull(valueAfterExpiration,
                                "NODEAUDIT entries must not remain readable after MaxLife"));
            } finally {
                rawCache.remove(key);
            }
        }
    }

    private Properties loadCacheProperties() throws IOException {
        Properties properties = new Properties();
        try (InputStream input = getClass().getClassLoader().getResourceAsStream(CACHE_PROPERTIES)) {
            assertNotNull(input, CACHE_PROPERTIES + " not found on classpath");
            properties.load(input);
        }
        return properties;
    }

    private void retainNodeAuditRegion(Properties properties) {
        new ArrayList<>(properties.stringPropertyNames()).stream()
                .filter(name -> name.startsWith("jcs.region.")
                        && !name.equals("jcs.region.NODEAUDIT")
                        && !name.startsWith("jcs.region.NODEAUDIT."))
                .forEach(properties::remove);
    }

    private List<Advisory> pollUntilExpired(DataCache<List<Advisory>> cache, String key)
            throws InterruptedException {
        long start = System.nanoTime();
        List<Advisory> value = cache.get(key);
        while (value != null && System.nanoTime() - start < EXPIRATION_TIMEOUT_NANOS) {
            Thread.sleep(POLL_INTERVAL_MILLIS);
            value = cache.get(key);
        }
        return value;
    }

    /**
     * A cache manager with a lifecycle scoped to one test.
     */
    private static final class ScopedCacheManager extends CompositeCacheManager implements AutoCloseable {

        private ScopedCacheManager(Properties properties) {
            setJmxName(null);
            initialize();
            configure(properties, false);
        }

        @Override
        public void close() {
            shutDown();
        }
    }
}
