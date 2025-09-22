package com.klu;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class CorsConfig {

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**") // allow all endpoints
                        .allowedOrigins("http://localhost:5173") // your React frontend
                        .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS") // all HTTP methods
                        .allowedHeaders("*") // allow all headers
                        .allowCredentials(true) // allow cookies, auth headers
                        .maxAge(3600); // preflight cache duration in seconds
            }
        };
    }
}
