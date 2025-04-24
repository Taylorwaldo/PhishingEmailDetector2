package com.waldotaylor.phishingdetector.web;

import com.waldotaylor.phishingdetector.main.PhishingDetector;
import com.waldotaylor.phishingdetector.model.Email;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*") // For development - restrict in production
public class PhishingDetectorController {

    private static final Pattern URL_PATTERN = Pattern.compile(
            "(https?://|www\\.)[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}\\b([-a-zA-Z0-9()@:%_\\+.~#?&//=]*)");

    @PostMapping("/analyze")
    public ResponseEntity<Map<String, Object>> analyzeEmail(@RequestBody EmailRequest request) {
        // Create Email object from request
        Email email = new Email(request.getSender(), request.getSubject(), request.getBody());

        // Add attachments
        if (request.getAttachments() != null) {
            for (String attachment : request.getAttachments()) {
                email.addAttachment(attachment);
            }
        }

        // Explicitly extract links from body (this might be redundant as BodyAnalyzer does this too,
        // but ensures links are available in the response)
        extractLinks(email);

        // Analyze the email
        int phishingScore = PhishingDetector.analyzeEmail(email);

        // Generate the detailed report
        String report = PhishingDetector.generateReport(email, phishingScore);

        // Build and return the response
        Map<String, Object> response = buildResponse(email, phishingScore, report);
        return ResponseEntity.ok(response);
    }

    private void extractLinks(Email email) {
        String body = email.getBody();
        Matcher urlMatcher = URL_PATTERN.matcher(body);
        while (urlMatcher.find()) {
            String url = urlMatcher.group();
            email.addLink(url);
        }
    }

    private Map<String, Object> buildResponse(Email email, int phishingScore, String report) {
        Map<String, Object> response = new HashMap<>();

        // Basic information
        response.put("sender", email.getSender());
        response.put("subject", email.getSubject());
        response.put("bodyLength", email.getBody().length());
        response.put("links", email.getLinks());
        response.put("attachments", email.getAttachments());
        response.put("phishingScore", phishingScore);

        // Assessment
        String assessment;
        if (phishingScore < 15) {
            assessment = "This email appears to be SAFE. No significant phishing indicators detected.";
        } else if (phishingScore < 40) {
            assessment = "This email has SOME SUSPICIOUS elements but is likely legitimate. Proceed with caution.";
        } else if (phishingScore < 60) {
            assessment = "This email is MODERATELY SUSPICIOUS and may be a phishing attempt. Verify before taking any action.";
        } else {
            assessment = "This email is HIGHLY SUSPICIOUS and likely a phishing attempt. Do not click links, download attachments, or respond with personal information.";
        }
        response.put("assessment", assessment);

        // Parse report to extract suspicious elements
        List<Map<String, Object>> suspiciousElements = extractSuspiciousElements(report);
        response.put("suspiciousElements", suspiciousElements);

        // Full report for reference
        response.put("fullReport", report);

        return response;
    }

    private List<Map<String, Object>> extractSuspiciousElements(String report) {
        List<Map<String, Object>> elements = new ArrayList<>();

        // This is a simplified parser that extracts suspicious elements from the report
        // In a real implementation, you might want to build these elements directly
        // rather than parsing them from the text report

        String[] lines = report.split("\n");
        boolean inSuspiciousSection = false;

        Map<String, Object> currentElement = null;
        List<String> details = null;

        for (String line : lines) {
            if (line.contains("Suspicious Elements:")) {
                inSuspiciousSection = true;
                continue;
            }

            if (inSuspiciousSection) {
                if (line.contains("Safety Recommendations:")) {
                    inSuspiciousSection = false;
                    continue;
                }

                if (line.startsWith("- ")) {
                    // Start of a new suspicious element
                    if (currentElement != null) {
                        // Add the previous element to the list
                        currentElement.put("details", details);
                        elements.add(currentElement);
                    }

                    currentElement = new HashMap<>();
                    details = new ArrayList<>();

                    // Parse the element type and score
                    String elementText = line.substring(2); // Remove "- "

                    // Extract element type
                    String elementType = "";
                    if (elementText.contains("Sender issues")) {
                        elementType = "sender";
                    } else if (elementText.contains("Subject line")) {
                        elementType = "subject";
                    } else if (elementText.contains("Suspicious links")) {
                        elementType = "links";
                    } else if (elementText.contains("Content contains")) {
                        elementType = "content";
                    } else if (elementText.contains("attachments")) {
                        elementType = "attachments";
                    }

                    // Extract score
                    int score = 0;
                    if (elementText.contains("score: ")) {
                        String scoreStr = elementText.substring(
                                elementText.indexOf("score: ") + 7,
                                elementText.indexOf(")")
                        );
                        score = Integer.parseInt(scoreStr);
                    }

                    currentElement.put("type", elementType);
                    currentElement.put("score", score);
                    currentElement.put("description", elementText);
                } else if (line.trim().startsWith("*") || line.trim().startsWith("-")) {
                    // Detail about the suspicious element
                    details.add(line.trim());
                }
            }
        }

        // Add the last element if any
        if (currentElement != null) {
            currentElement.put("details", details);
            elements.add(currentElement);
        }

        return elements;
    }
}

// Request DTO class
class EmailRequest {
    private String sender;
    private String subject;
    private String body;
    private List<String> attachments;

    // Getters and setters
    public String getSender() {
        return sender;
    }

    public void setSender(String sender) {
        this.sender = sender;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public String getBody() {
        return body;
    }

    public void setBody(String body) {
        this.body = body;
    }

    public List<String> getAttachments() {
        return attachments;
    }

    public void setAttachments(List<String> attachments) {
        this.attachments = attachments;
    }
}