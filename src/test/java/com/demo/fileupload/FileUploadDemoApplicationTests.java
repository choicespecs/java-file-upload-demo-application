package com.demo.fileupload;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * Smoke test that verifies the Spring application context loads successfully.
 *
 * <p>This test catches configuration errors, missing beans, and property binding failures
 * early without requiring any application logic to be exercised. If this test fails,
 * no other test in the suite is likely to pass.
 */
@SpringBootTest
class FileUploadDemoApplicationTests {

    /**
     * Verifies that the Spring application context initialises without errors.
     * No assertions are needed — a failure during context startup causes the test to fail.
     */
    @Test
    void contextLoads() {
    }
}
