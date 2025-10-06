        // Phishing keywords and patterns
        const phishingKeywords = [
            'urgent', 'immediate action', 'suspended', 'verify your account', 'click here now',
            'limited time', 'act now', 'confirm your identity', 'update your information',
            'security alert', 'unusual activity', 'temporarily blocked', 'expires today',
            'winner', 'congratulations', 'free money', 'claim your prize', 'tax refund'
        ];

        const suspiciousDomains = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co',
            'secure-bank', 'verify-account', 'security-update',
            'paypal-security', 'amazon-verify', 'apple-id'
        ];

        function switchTab(tabName) {
            // Hide all tab contents
            const tabContents = document.querySelectorAll('.tab-content');
            tabContents.forEach(content => content.classList.remove('active'));
            
            // Remove active class from all tabs
            const tabs = document.querySelectorAll('.tab');
            tabs.forEach(tab => tab.classList.remove('active'));
            
            // Show selected tab content
            document.getElementById(tabName).classList.add('active');
            
            // Add active class to clicked tab
            event.target.classList.add('active');
        }

        function analyzeEmail() {
            const sender = document.getElementById('sender-email').value.toLowerCase();
            const subject = document.getElementById('email-subject').value.toLowerCase();
            const content = document.getElementById('email-content').value.toLowerCase();
            
            let riskScore = 0;
            let indicators = [];
            
            // Analyze sender
            if (sender.includes('noreply') || sender.includes('donotreply')) {
                riskScore += 10;
            }
            
            // Check for suspicious domain patterns
            suspiciousDomains.forEach(domain => {
                if (sender.includes(domain)) {
                    riskScore += 30;
                    indicators.push({
                        level: 'high',
                        message: `Suspicious domain detected in sender: ${domain}`
                    });
                }
            });
            
            // Analyze subject
            if (subject.includes('urgent') || subject.includes('immediate')) {
                riskScore += 25;
                indicators.push({
                    level: 'high',
                    message: 'Subject contains urgent language'
                });
            }
            
            if (subject.includes('suspended') || subject.includes('blocked')) {
                riskScore += 30;
                indicators.push({
                    level: 'high',
                    message: 'Subject mentions account suspension/blocking'
                });
            }
            
            // Analyze content
            phishingKeywords.forEach(keyword => {
                if (content.includes(keyword)) {
                    riskScore += 15;
                    indicators.push({
                        level: 'medium',
                        message: `Suspicious keyword detected: "${keyword}"`
                    });
                }
            });
            
            // Check for generic greetings
            if (content.includes('dear customer') || content.includes('dear user') || content.includes('valued customer')) {
                riskScore += 20;
                indicators.push({
                    level: 'medium',
                    message: 'Generic greeting detected (not personalized)'
                });
            }
            
            // Check for URL shorteners or suspicious links
            const urlPattern = /(https?:\/\/[^\s]+)/gi;
            const urls = content.match(urlPattern) || [];
            urls.forEach(url => {
                suspiciousDomains.forEach(domain => {
                    if (url.includes(domain)) {
                        riskScore += 25;
                        indicators.push({
                            level: 'high',
                            message: `Suspicious link detected: ${url.substring(0, 50)}...`
                        });
                    }
                });
            });
            
            displayEmailResult(riskScore, indicators);
        }
        
        function displayEmailResult(riskScore, indicators) {
            const resultDiv = document.getElementById('email-result');
            const titleEl = document.getElementById('email-result-title');
            const messageEl = document.getElementById('email-result-message');
            const indicatorsEl = document.getElementById('email-indicators');
            
            resultDiv.className = 'result';
            
            if (riskScore >= 60) {
                resultDiv.classList.add('dangerous');
                titleEl.textContent = '🚨 High Risk - Likely Phishing';
                messageEl.textContent = 'This email shows multiple signs of being a phishing attempt. Do not interact with any links or provide personal information.';
            } else if (riskScore >= 30) {
                resultDiv.classList.add('suspicious');
                titleEl.textContent = '⚠️ Suspicious - Exercise Caution';
                messageEl.textContent = 'This email contains some suspicious elements. Verify the sender through official channels before taking any action.';
            } else {
                resultDiv.classList.add('safe');
                titleEl.textContent = '✅ Appears Safe';
                messageEl.textContent = 'No obvious phishing indicators detected. However, always remain vigilant and trust your instincts.';
            }
            
            // Display indicators
            indicatorsEl.innerHTML = '';
            indicators.forEach(indicator => {
                const div = document.createElement('div');
                div.className = `risk-indicator ${indicator.level}`;
                div.innerHTML = `
                    <div class="icon">${indicator.level === 'high' ? '!' : indicator.level === 'medium' ? '?' : '✓'}</div>
                    <span>${indicator.message}</span>
                `;
                indicatorsEl.appendChild(div);
            });
            
            resultDiv.style.display = 'block';
        }
        
        function analyzeURL() {
            const url = document.getElementById('url-input').value.toLowerCase();
            
            if (!url) {
                alert('Please enter a URL to analyze');
                return;
            }
            
            let riskScore = 0;
            let indicators = [];
            
            // Check for HTTPS
            if (!url.startsWith('https://')) {
                riskScore += 20;
                indicators.push({
                    level: 'medium',
                    message: 'URL does not use HTTPS encryption'
                });
            }
            
            // Check for suspicious domains
            suspiciousDomains.forEach(domain => {
                if (url.includes(domain)) {
                    riskScore += 40;
                    indicators.push({
                        level: 'high',
                        message: `Contains suspicious domain: ${domain}`
                    });
                }
            });
            
            // Check for URL shorteners
            const shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'short.link'];
            shorteners.forEach(shortener => {
                if (url.includes(shortener)) {
                    riskScore += 25;
                    indicators.push({
                        level: 'medium',
                        message: 'Uses URL shortening service (destination hidden)'
                    });
                }
            });
            
            // Check for suspicious patterns
            const suspiciousPatterns = [
                'verify', 'secure', 'account', 'login', 'bank', 'paypal', 'amazon',
                'apple', 'microsoft', 'google', 'facebook'
            ];
            
            suspiciousPatterns.forEach(pattern => {
                if (url.includes(pattern) && !url.includes(`${pattern}.com`)) {
                    riskScore += 15;
                    indicators.push({
                        level: 'medium',
                        message: `Contains brand name in suspicious context: ${pattern}`
                    });
                }
            });
            
            // Check for IP addresses instead of domain names
            const ipPattern = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/;
            if (ipPattern.test(url)) {
                riskScore += 35;
                indicators.push({
                    level: 'high',
                    message: 'Uses IP address instead of domain name'
                });
            }
            
            displayURLResult(riskScore, indicators);
        }
        
        function displayURLResult(riskScore, indicators) {
            const resultDiv = document.getElementById('url-result');
            const titleEl = document.getElementById('url-result-title');
            const messageEl = document.getElementById('url-result-message');
            const indicatorsEl = document.getElementById('url-indicators');
            
            resultDiv.className = 'result';
            
            if (riskScore >= 50) {
                resultDiv.classList.add('dangerous');
                titleEl.textContent = '🚨 High Risk URL';
                messageEl.textContent = 'This URL shows multiple suspicious characteristics. Avoid visiting this link.';
            } else if (riskScore >= 25) {
                resultDiv.classList.add('suspicious');
                titleEl.textContent = '⚠️ Potentially Suspicious URL';
                messageEl.textContent = 'This URL contains some concerning elements. Proceed with caution and verify authenticity.';
            } else {
                resultDiv.classList.add('safe');
                titleEl.textContent = '✅ URL Appears Safe';
                messageEl.textContent = 'No obvious suspicious indicators detected in this URL.';
            }
            
            // Display indicators
            indicatorsEl.innerHTML = '';
            indicators.forEach(indicator => {
                const div = document.createElement('div');
                div.className = `risk-indicator ${indicator.level}`;
                div.innerHTML = `
                    <div class="icon">${indicator.level === 'high' ? '!' : indicator.level === 'medium' ? '?' : '✓'}</div>
                    <span>${indicator.message}</span>
                `;
                indicatorsEl.appendChild(div);
            });
            
            resultDiv.style.display = 'block';
        }
        
        function checkQuiz() {
            const answers = {
                q1: 'b', // Urgent language demanding immediate action
                q2: 'c', // Delete it and report it as spam
                q3: 'b'  // amaz0n-security.net/verify (typosquatting)
            };
            
            let score = 0;
            let feedback = [];
            
            Object.keys(answers).forEach(question => {
                const selected = document.querySelector(`input[name="${question}"]:checked`);
                if (selected && selected.value === answers[question]) {
                    score++;
                    feedback.push(`Question ${question.slice(-1)}: Correct! ✅`);
                } else {
                    feedback.push(`Question ${question.slice(-1)}: Incorrect ❌`);
                }
            });
            
            const resultDiv = document.getElementById('quiz-result');
            const scoreEl = document.getElementById('quiz-score');
            const feedbackEl = document.getElementById('quiz-feedback');
            
            scoreEl.textContent = `Your Score: ${score}/3 (${Math.round(score/3*100)}%)`;
            
            let resultClass = 'safe';
            let message = '';
            
            if (score === 3) {
                resultClass = 'safe';
                message = 'Excellent! You have a strong understanding of phishing detection.';
            } else if (score === 2) {
                resultClass = 'suspicious';
                message = 'Good job! Review the guide to improve your phishing detection skills.';
            } else {
                resultClass = 'dangerous';
                message = 'Consider reviewing the awareness guide to better protect yourself from phishing attacks.';
            }
            
            resultDiv.className = `quiz-result ${resultClass}`;
            feedbackEl.innerHTML = `
                <p style="margin-bottom: 15px;"><strong>${message}</strong></p>
                <div>${feedback.map(f => `<p>${f}</p>`).join('')}</div>
                <div style="margin-top: 15px;">
                    <p><strong>Correct Answers:</strong></p>
                    <p>1. Urgent language demanding immediate action</p>
                    <p>2. Delete it and report it as spam</p>
                    <p>3. https://amaz0n-security.net/verify (typosquatting attack)</p>
                </div>
            `;
            
            resultDiv.style.display = 'block';
        }