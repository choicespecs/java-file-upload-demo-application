package com.demo.fileupload.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * MVC controller that serves the static SPA HTML pages.
 *
 * <p>Thymeleaf is used only as a static file delivery mechanism — no model attributes
 * are added and no Thymeleaf expressions appear in the templates. All dynamic behaviour
 * is handled client-side by {@code app.js}, which fetches data from the REST API.
 *
 * <p>These routes are publicly accessible (no authentication required) as configured
 * in {@link com.demo.fileupload.config.SecurityConfig}. The frontend JavaScript in
 * {@code login.html} and {@code register.html} redirects to {@code /} after a successful
 * auth call, and {@code app.js} redirects to {@code /login} if no JWT is found in
 * {@code localStorage}.
 */
@Controller
public class WebController {

    /**
     * Serves the main file-management single-page application shell ({@code index.html}).
     *
     * @return the Thymeleaf view name {@code "index"}
     */
    @GetMapping("/")
    public String index() {
        return "index";
    }

    /**
     * Serves the login page ({@code login.html}).
     *
     * @return the Thymeleaf view name {@code "login"}
     */
    @GetMapping("/login")
    public String login() {
        return "login";
    }

    /**
     * Serves the registration page ({@code register.html}).
     *
     * @return the Thymeleaf view name {@code "register"}
     */
    @GetMapping("/register")
    public String register() {
        return "register";
    }
}
