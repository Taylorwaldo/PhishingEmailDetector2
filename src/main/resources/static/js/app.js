document.addEventListener('DOMContentLoaded', function() {
    // DOM elements
    const addAttachmentBtn = document.getElementById('add-attachment');
    const attachmentsContainer = document.getElementById('attachments-container');
    const analyzeBtn = document.getElementById('analyze-btn');
    const backBtn = document.getElementById('back-btn');
    const inputForm = document.getElementById('input-form');
    const resultsSection = document.getElementById('results');

    // Add attachment field
    addAttachmentBtn.addEventListener('click', function() {
        const attachmentInputs = document.querySelectorAll('.attachment-input');
        const lastInput = attachmentInputs[attachmentInputs.length - 1];
        const lastInputValue = lastInput.querySelector('.attachment-name').value.trim();

        // If the last input is empty, don't add a new one
        if (lastInputValue === '') {
            return;
        }

        // Show remove button for all existing attachment inputs
        document.querySelectorAll('.remove-attachment').forEach(btn => {
            btn.style.display = 'block';
        });

        // Create new attachment input
        const newAttachmentInput = document.createElement('div');
        newAttachmentInput.className = 'attachment-input';
        newAttachmentInput.innerHTML = `
            <input type="text" placeholder="attachment2.pdf" class="attachment-name">
            <button type="button" class="btn-danger remove-attachment">X</button>
        `;

        attachmentsContainer.appendChild(newAttachmentInput);

        // Add event listener to remove button
        const removeBtn = newAttachmentInput.querySelector('.remove-attachment');
        removeBtn.addEventListener('click', function() {
            newAttachmentInput.remove();

            // If only one attachment input is left, hide its remove button
            const remainingInputs = document.querySelectorAll('.attachment-input');
            if (remainingInputs.length === 1) {
                remainingInputs[0].querySelector('.remove-attachment').style.display = 'none';
            }
        });
    });

    // Remove attachment field (handle initial and dynamic elements)
    document.addEventListener('click', function(e) {
        if (e.target && e.target.classList.contains('remove-attachment')) {
            e.target.parentElement.remove();

            // If only one attachment input is left, hide its remove button
            const remainingInputs = document.querySelectorAll('.attachment-input');
            if (remainingInputs.length === 1) {
                remainingInputs[0].querySelector('.remove-attachment').style.display = 'none';
            }
        }
    });

    // Analyze email button click handler
    analyzeBtn.addEventListener('click', function() {
        // Get input values
        const sender = document.getElementById('sender').value.trim();
        const subject = document.getElementById('subject').value.trim();
        const body = document.getElementById('body').value.trim();

        // Validate required fields
        if (sender === '' || subject === '' || body === '') {
            alert('Please fill in all required fields (sender, subject, and body).');
            return;
        }

        // Get attachments
        const attachmentInputs = document.querySelectorAll('.attachment-name');
        const attachments = [];

        attachmentInputs.forEach(input => {
            const attachment = input.value.trim();
            if (attachment !== '') {
                attachments.push(attachment);
            }
        });

        // Process the email with API
        analyzeEmail({
            sender: sender,
            subject: subject,
            body: body,
            attachments: attachments
        });
    });

    // Go back to input form
    backBtn.addEventListener('click', function() {
        inputForm.style.display = 'block';
        resultsSection.style.display = 'none';
    });

    // Function to analyze an email via the API
    function analyzeEmail(email) {
        // Show loading indicator
        const analyzeBtn = document.getElementById('analyze-btn');
        analyzeBtn.textContent = 'Analyzing...';
        analyzeBtn.disabled = true;

        // Make API call to your Spring Boot backend
        fetch('/api/analyze', {
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
                links: data.links || [],
                attachments: data.attachments || [],
                phishingScore: data.phishingScore,
                assessment: data.assessment,
                suspiciousElements: data.suspiciousElements || []
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

    // Function to display results
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
        inputForm.style.display = 'none';
        resultsSection.style.display = 'block';
    }
});