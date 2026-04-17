package com.demo.fileupload;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Application entry point for the File Upload Demo.
 *
 * <p>Bootstraps the Spring application context. All configuration is loaded from
 * {@code application.properties} (dev, H2) or {@code application-prod.properties}
 * (prod, PostgreSQL) via the {@code app.*} property namespace defined in
 * {@link com.demo.fileupload.config.AppProperties}.
 */
@SpringBootApplication
public class FileUploadDemoApplication {

    /**
     * Launches the embedded Tomcat server and initialises the Spring context.
     *
     * @param args command-line arguments passed through to {@link SpringApplication#run}
     */
    public static void main(String[] args) {
        SpringApplication.run(FileUploadDemoApplication.class, args);
    }
}
