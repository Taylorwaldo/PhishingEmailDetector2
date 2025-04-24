// Replace the analyzeEmail function in your HTML file with this version
function analyzeEmail(email) {
    // Show loading indicator (you could add a spinner to your HTML)
    const analyzeBtn = document.getElementById('analyze-btn');
    analyzeBtn.textContent = 'Analyzing...';
    analyzeBtn.disabled = true;

    // Make API call to your Spring Boot backend
    fetch('http://localhost:8080/api/analyze', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            sender: email.sender,
            subject: email.subject,
            body: email.body,
            attachments: email.attachments
        })
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json();
    })
    .then(data => {
        // Reset button
        analyzeBtn.textContent = 'Analyze Email';
        analyzeBtn.disabled = false;

        // Display the results
        displayResults({
            sender: data.sender,
            subject: data.subject,
            bodyLength: data.bodyLength,
            links: data.links,
            attachments: data.attachments,
            phishingScore: data.phishingScore,
            assessment: data.assessment,
            suspiciousElements: data.suspiciousElements
        });
    })
    .catch(error => {
        console.error('Error:', error);
        alert('An error occurred while analyzing the email. Please try again.');

        // Reset button
        analyzeBtn.textContent = 'Analyze Email';
        analyzeBtn.disabled = false;
    });
}

// You'll also need to update the displayResults function to handle the new data format
function displayResults(results) {
    // Update basic information
    document.getElementById('result-sender').textContent = results.sender;
    document.getElementById('result-subject').textContent = results.subject;
    document.getElementById('result-body-length').textContent = results.bodyLength;
    document.getElementById('result-links').textContent = results.links.length;
    document.getElementById('result-attachments').textContent = results.attachments.length;

    // Update score gauge
    const gaugeFill = document.getElementById('gauge-fill');
    const scoreText = document.getElementById('score-text');

    scoreText.textContent = results.phishingScore;
    const fillHeight = (results.phishingScore / 100) * 100;
    gaugeFill.style.height = `${fillHeight}%`;

    // Set gauge color based on score
    if (results.phishingScore < 15) {
        gaugeFill.style.backgroundColor = 'var(--success-color)';
    } else if (results.phishingScore < 40) {
        gaugeFill.style.backgroundColor = 'var(--warning-color)';
    } else if (results.phishingScore < 60) {
        gaugeFill.style.backgroundColor = 'var(--warning-color)';
    } else {
        gaugeFill.style.backgroundColor = 'var(--danger-color)';
    }

    // Update assessment
    const assessment = document.getElementById('assessment');

    if (results.phishingScore < 15) {
        assessment.className = 'assessment safe';
    } else if (results.phishingScore < 40) {
        assessment.className = 'assessment suspicious';
    } else if (results.phishingScore < 60) {
        assessment.className = 'assessment moderate';
    } else {
        assessment.className = 'assessment high';
    }
    assessment.textContent = 'ASSESSMENT: ' + results.assessment;

    // Update suspicious elements
    const suspiciousElements = document.getElementById('suspicious-elements');
    suspiciousElements.innerHTML = '<h3>Suspicious Elements</h3>';

    // Check if there are any suspicious elements to report
    if (results.suspiciousElements && results.suspiciousElements.length > 0) {
        results.suspiciousElements.forEach(element => {
            const elementDiv = document.createElement('div');
            elementDiv.className = 'suspicious-element';

            let elementHtml = `<h4>${element.description}</h4>`;

            // If this element has details or sub-items
            if (element.details && element.details.length > 0) {
                if (element.type === 'links' || element.type === 'attachments') {
                    elementHtml += `<ul class="suspicious-${element.type}">`;
                    element.details.forEach(detail => {
                        elementHtml += `<li>${detail}</li>`;
                    });
                    elementHtml += '</ul>';
                } else {
                    element.details.forEach(detail => {
                        elementHtml += `<p>${detail}</p>`;
                    });
                }
            }

            elementDiv.innerHTML = elementHtml;
            suspiciousElements.appendChild(elementDiv);
        });
    } else {
        const noSuspiciousElement = document.createElement('p');
        noSuspiciousElement.textContent = 'No suspicious elements detected.';
        suspiciousElements.appendChild(noSuspiciousElement);
    }

    // Show results section and hide input form
    document.getElementById('input-form').style.display = 'none';
    document.getElementById('results').style.display = 'block';
}