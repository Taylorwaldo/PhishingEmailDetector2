package com.waldotaylor.phishingdetector.web;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan(basePackages = {"com.waldotaylor.phishingdetector"})
public class PhishingDetectorWebApplication {

    public static void main(String[] args) {
        SpringApplication.run(PhishingDetectorWebApplication.class, args);
    }
}