package com.waldotaylor.phishingdetector.service;

import com.waldotaylor.phishingdetector.analysis.*;
import com.waldotaylor.phishingdetector.model.Email;

import java.util.ArrayList;
import java.util.List;

/**
 * Main class that coordinates the analysis of emails
 * Runs multiple analyzers and combines their scores
 */
public class PhishingDetector {
    private static final List<ThreatDetector> analyzers = new ArrayList<>();

    // Initialize the analyzers list
    static {
        analyzers.add(new SenderAnalyzer());
        analyzers.add(new HeaderAnalyzer());
        analyzers.add(new ContentAnalyzer());
        analyzers.add(new BodyAnalyzer());
        analyzers.add(new LinkAnalyzer());
        analyzers.add(new AttachmentAnalyzer());
    }

    /**
     * Analyzes an email using all available analyzers
     * @param email The email to analyze
     * @return A score from 0-100 indicating the overall phishing threat level
     */
    public static int analyzeEmail(Email email) {
        // First run the BodyAnalyzer to extract links and potential attachments
        int bodyScore = 0;
        for (ThreatDetector analyzer : analyzers) {
            if (analyzer instanceof BodyAnalyzer) {
                bodyScore = analyzer.analyze(email);
                break;
            }
        }

        // Then run all other analyzers
        List<Integer> scores = new ArrayList<>();
        scores.add(bodyScore); // Add the BodyAnalyzer score

        for (ThreatDetector analyzer : analyzers) {
            if (!(analyzer instanceof BodyAnalyzer)) { // Skip BodyAnalyzer as we already ran it
                int score = analyzer.analyze(email);
                scores.add(score);
            }
        }

        // Calculate the weighted average
        // We give more weight to the highest scores to ensure serious threats aren't missed
        if (scores.isEmpty()) {
            return 0;
        }

        // Sort scores in descending order
        scores.sort((a, b) -> b - a);

        // Weight calculation: highest score gets the most weight
        double totalWeight = 0;
        double weightedSum = 0;

        for (int i = 0; i < scores.size(); i++) {
            double weight = Math.pow(0.8, i); // Exponential decay of weights
            totalWeight += weight;
            weightedSum += scores.get(i) * weight;
        }

        int finalScore = (int) Math.round(weightedSum / totalWeight);
        return Math.min(finalScore, 100); // Cap at 100
    }

    /**
     * Generates a detailed report of the analysis results
     * @param email The analyzed email
     * @param phishingScore The overall phishing score
     * @return A formatted report string
     */
    public static String generateReport(Email email, int phishingScore) {
        StringBuilder report = new StringBuilder();

        // Email information
        report.append("PHISHING DETECTION REPORT\n");
        report.append("========================\n\n");
        report.append("EMAIL DETAILS:\n");
        report.append("Sender: ").append(email.getSender()).append("\n");
        report.append("Subject: ").append(email.getSubject()).append("\n");
        report.append("Body Length: ").append(email.getBody().length()).append(" characters\n");
        report.append("Links Found: ").append(email.getLinks().size()).append("\n");
        report.append("Attachments Found: ").append(email.getAttachments().size()).append("\n\n");

        // Overall assessment
        report.append("OVERALL ASSESSMENT:\n");
        report.append("Phishing Probability Score: ").append(phishingScore).append("/100\n");

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
        report.append(assessment).append("\n\n");

        // Individual analyzer scores
        report.append("ANALYSIS DETAILS:\n");
        List<ThreatDetector> detectors = new ArrayList<>(analyzers);

        // Run each analyzer and capture results
        for (ThreatDetector detector : detectors) {
            int score = detector.analyze(email);
            if (score > 0) {
                report.append("- ").append(detector.getDetectorName())
                        .append(" Score: ").append(score).append("/100\n");
            }
        }
        report.append("\n");

        // List suspicious elements if score is high enough
        if (phishingScore >= 15) {
            report.append("Suspicious Elements:\n");

            // Sender analysis
            if (email.getSender() != null) {
                SenderAnalyzer senderAnalyzer = new SenderAnalyzer();
                int senderScore = senderAnalyzer.analyze(email);
                if (senderScore > 0) {
                    report.append("- Sender issues detected (score: ").append(senderScore).append(")\n");
                    if (senderScore >= 50) {
                        report.append("  * Invalid email format or highly suspicious domain\n");
                    } else if (senderScore >= 30) {
                        report.append("  * Suspicious domain or unusual sender name\n");
                    } else {
                        report.append("  * Minor issues with sender address\n");
                    }
                }
            }

            // Header analysis
            HeaderAnalyzer headerAnalyzer = new HeaderAnalyzer();
            int headerScore = headerAnalyzer.analyze(email);
            if (headerScore > 0) {
                report.append("- Subject line contains suspicious language (score: ").append(headerScore).append(")\n");
            }

            // Content analysis
            ContentAnalyzer contentAnalyzer = new ContentAnalyzer();
            int contentScore = contentAnalyzer.analyze(email);
            if (contentScore > 0) {
                report.append("- Content contains suspicious language or requests (score: ").append(contentScore).append(")\n");
                if (contentScore >= 40) {
                    report.append("  * Multiple phishing keywords detected\n");
                }
                if (contentScore >= 15) {
                    report.append("  * Contains requests for sensitive information\n");
                }
                if (contentScore >= 10) {
                    report.append("  * Unusual formatting or excessive urgency indicators\n");
                }
            }

            // Link analysis
            LinkAnalyzer linkAnalyzer = new LinkAnalyzer();
            int linkScore = linkAnalyzer.analyze(email);
            if (linkScore > 0 && !email.getLinks().isEmpty()) {
                report.append("- Suspicious links detected (score: ").append(linkScore).append(")\n");
                for (String link : email.getLinks()) {
                    report.append("  * ").append(link).append("\n");
                }
            }

            // Attachment analysis
            AttachmentAnalyzer attachmentAnalyzer = new AttachmentAnalyzer();
            int attachmentScore = attachmentAnalyzer.analyze(email);
            if (attachmentScore > 0 && !email.getAttachments().isEmpty()) {
                report.append("- Potentially dangerous attachments detected (score: ").append(attachmentScore).append(")\n");
                for (String attachment : email.getAttachments()) {
                    report.append("  * ").append(attachment).append("\n");
                }
            }
        }

        // Safety recommendations
        report.append("\nSafety Recommendations:\n");
        report.append("1. Always verify the sender's email address\n");
        report.append("2. Do not click on suspicious links - hover over them first to see where they lead\n");
        report.append("3. Never download attachments unless you are expecting them\n");
        report.append("4. Contact the supposed sender through official channels if unsure\n");
        report.append("5. Never provide sensitive information (passwords, credit cards) in response to an email\n");

        return report.toString();
    }
}