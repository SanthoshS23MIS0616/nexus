package com.cybershield;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

/**
 * Basic smoke test — verifies the Spring application context loads without errors.
 * Run with: mvn test
 */
@SpringBootTest
class CyberShieldNexusApplicationTests {

    @Test
    void contextLoads() {
        // If this test passes, the entire Spring context
        // (Security config, JPA, JWT, all beans) wired up correctly
    }
}
