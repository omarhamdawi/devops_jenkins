package com.example.petclinic;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
public class PetclinicApplication {

    public static void main(String[] args) {
        SpringApplication.run(PetclinicApplication.class, args);
    }

    @GetMapping("/")
    public String home() {
        return "PetClinic Application is running! 🐾";
    }

    @GetMapping("/actuator/health")
    public String health() {
        return "{\"status\":\"UP\"}";
    }
    
    @GetMapping("/info")
    public String info() {
        return "PetClinic API v1.0";
    }
}
