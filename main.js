// AI Spam Shield - Main JavaScript
// Professional email security application with deterministic threat analysis

class SpamShield {
    constructor() {
        this.backendUrl =
            window.location.hostname === 'localhost' ||
            window.location.hostname === '127.0.0.1'
                ? 'http://localhost:5000'
                : '';

        this.isAnalyzing = false;
        this.currentAnalysis = null;
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.initializeAnimations();
        this.populateRecentActivity();
        this.startRealTimeUpdates();
        this.loadStatistics();
    }

    setupEventListeners() {
        // Email input analysis
        const emailInput = document.getElementById('email-input');
        const analyzeBtn = document.getElementById('analyze-btn');
        const clearBtn = document.getElementById('clear-btn');
        
        if (emailInput) {
            emailInput.addEventListener('input', (e) => {
                const charCount = document.getElementById('char-count');
                if (charCount) {
                    charCount.textContent = e.target.value.length;
                }
            });
        }

        if (analyzeBtn) {
            analyzeBtn.addEventListener('click', () => this.analyzeEmail());
        }

        if (clearBtn) {
            clearBtn.addEventListener('click', () => this.clearInput());
        }

        // Action buttons
        const blockBtn = document.getElementById('block-sender');
        const reportBtn = document.getElementById('report-threat');
        const whitelistBtn = document.getElementById('whitelist-sender');

        if (blockBtn) blockBtn.addEventListener('click', () => this.blockSender());
        if (reportBtn) reportBtn.addEventListener('click', () => this.reportThreat());
        if (whitelistBtn) whitelistBtn.addEventListener('click', () => this.whitelistSender());

        // Add hover effects to interactive elements
        document.querySelectorAll('.glass-panel, .btn-primary, .btn-secondary').forEach(element => {
            element.addEventListener('mouseenter', this.addHoverEffect);
            element.addEventListener('mouseleave', this.removeHoverEffect);
        });
    }

    addHoverEffect(e) {
        if (e.target.classList.contains('glass-panel')) {
            anime({
                targets: e.target,
                scale: 1.02,
                duration: 300,
                easing: 'easeOutExpo'
            });
        }
    }

    removeHoverEffect(e) {
        if (e.target.classList.contains('glass-panel')) {
            anime({
                targets: e.target,
                scale: 1,
                duration: 300,
                easing: 'easeOutExpo'
            });
        }
    }

    initializeAnimations() {
        // Animate panels on scroll
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    anime({
                        targets: entry.target,
                        opacity: [0, 1],
                        translateY: [30, 0],
                        duration: 800,
                        easing: 'easeOutExpo'
                    });
                }
            });
        });

        document.querySelectorAll('.glass-panel').forEach(panel => {
            observer.observe(panel);
        });
    }

    async analyzeEmail() {
        const emailInput = document.getElementById('email-input');
        const emailContent = emailInput.value.trim();
        
        if (!emailContent) {
            this.showNotification('Please enter email content to analyze', 'warning');
            return;
        }

        if (this.isAnalyzing) return;
        this.isAnalyzing = true;

        // Show loading state
        this.showLoadingState();
        
        try {
            // Call backend API
            const response = await fetch(`${this.backendUrl}/api/analyze`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email: emailContent })
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const result = await response.json();
            this.displayAnalysisResults(result);
            this.updateThreatMeter(result.overall_score, result.risk_level);
            updateThreatCircle(result.overall_score);

            
        } catch (error) {
            console.error('Analysis error:', error);
            this.showNotification('Analysis failed. Please check if the backend server is running.', 'error');
            // Fallback to client-side analysis if backend is not available
            this.performClientSideAnalysis(emailContent);
        } finally {
            this.isAnalyzing = false;
            this.hideLoadingState();
        }
    }

    performClientSideAnalysis(emailContent) {
        // Client-side fallback analysis
        const result = this.clientSideAnalyzer(emailContent);
        this.displayAnalysisResults(result);
        this.updateThreatMeter(result.overall_score, result.risk_level);
        updateThreatCircle(result.overall_score);

    }

    clientSideAnalyzer(content) {
        // Simplified client-side analysis for fallback
        let phishingScore = 0;
        let scamScore = 0;
        let spamScore = 0;
        let socialScore = 0;

        const lowerContent = content.toLowerCase();

        // Phishing keywords
        const phishingKeywords = ['urgent', 'verify', 'confirm', 'suspended', 'security breach'];
        phishingKeywords.forEach(keyword => {
            if (lowerContent.includes(keyword)) phishingScore += 5;
        });

        // Scam keywords
        const scamKeywords = ['wire transfer', 'bitcoin', 'lottery winner', 'inheritance'];
        scamKeywords.forEach(keyword => {
            if (lowerContent.includes(keyword)) scamScore += 8;
        });

        // Spam keywords
        const spamKeywords = ['free', 'discount', 'buy now', 'unsubscribe'];
        spamKeywords.forEach(keyword => {
            if (lowerContent.includes(keyword)) spamScore += 3;
        });

        // Social engineering
        if (lowerContent.includes('ceo') && lowerContent.includes('urgent')) socialScore += 15;
        if (lowerContent.includes('confidential')) socialScore += 10;

        // URL analysis
        const urlPattern = /https?:\/\/[^\s]+/gi;
        const urls = content.match(urlPattern) || [];
        urls.forEach(url => {
            if (url.includes('bit.ly') || url.includes('tinyurl.com')) {
                phishingScore += 10;
            }
        });

        const overallScore = Math.min(Math.max(phishingScore, scamScore, spamScore, socialScore), 100);

        return {
            overall_score: overallScore,
            risk_level: this.getRiskLevel(overallScore),
            detailed_scores: {
                phishing: phishingScore,
                scam: scamScore,
                spam: spamScore,
                social_engineering: socialScore
            },
            explanation: this.generateClientSideExplanation(phishingScore, scamScore, spamScore, socialScore, content),
            indicators: {
                keywords_found: phishingKeywords.filter(kw => lowerContent.includes(kw)),
                suspicious_urls: urls.filter(url => url.includes('bit.ly') || url.includes('tinyurl.com'))
            }
        };
    }

    generateClientSideExplanation(phishing, scam, spam, social, content) {
        const explanations = [];

        if (phishing > 20) {
            explanations.push(`🎣 PHISHING DETECTED (${phishing}%): Contains urgency language or credential theft attempts.`);
        }
        if (scam > 20) {
            explanations.push(`💰 SCAM DETECTED (${scam}%): Contains financial manipulation or investment scam language.`);
        }
        if (spam > 20) {
            explanations.push(`📧 SPAM DETECTED (${spam}%): Contains promotional language or marketing terms.`);
        }
        if (social > 15) {
            explanations.push(`🎭 SOCIAL ENGINEERING (${social}%): Contains authority impersonation or manipulation tactics.`);
        }

        if (explanations.length === 0) {
            explanations.push("✅ EMAIL APPEARS SAFE: No significant threat indicators detected.");
        }

        return explanations.join('\n\n');
    }

    getRiskLevel(score) {
        if (score >= 80) return 'CRITICAL';
        if (score >= 60) return 'HIGH';
        if (score >= 40) return 'MEDIUM';
        if (score >= 20) return 'LOW';
        return 'SAFE';
    }

    showLoadingState() {
        const analyzeBtn = document.getElementById('analyze-btn');
        if (analyzeBtn) {
            analyzeBtn.innerHTML = '<div class="loading-spinner w-4 h-4 inline-block mr-2"></div>Analyzing...';
            analyzeBtn.disabled = true;
        }
    }

    hideLoadingState() {
        const analyzeBtn = document.getElementById('analyze-btn');
        if (analyzeBtn) {
            analyzeBtn.innerHTML = '🔍 Analyze Email';
            analyzeBtn.disabled = false;
        }
    }

    displayAnalysisResults(result) {
        if (result.risk_level === 'SAFE' && result.explanation.includes('TRUSTED')) {
        this.showNotification('Trusted sender — analysis bypassed', 'success');
    }

    if (result.risk_level === 'CRITICAL' && result.explanation.includes('BLOCKED')) {
        this.showNotification('Blocked sender detected', 'error');
    }

        const resultsDiv = document.getElementById('analysis-results');
        if (!resultsDiv) return;

        resultsDiv.classList.remove('hidden');
        resultsDiv.classList.add('fade-in');

        // Update detailed scores
        document.getElementById('phishing-score').textContent = `${result.detailed_scores.phishing}%`;
        document.getElementById('scam-score').textContent = `${result.detailed_scores.scam}%`;
        document.getElementById('spam-score').textContent = `${result.detailed_scores.spam}%`;
        document.getElementById('social-score').textContent = `${result.detailed_scores.social_engineering}%`;

        // Update explanation
        const explanationDiv = document.getElementById('analysis-details');
        if (explanationDiv) {
            explanationDiv.innerHTML = `<pre class="whitespace-pre-wrap">${result.explanation}</pre>`;

            // Append AI explanation if available
            if (result.ai_summary) {
                explanationDiv.innerHTML += `
                    <div class="mt-4 p-4 border border-cyan-400 rounded-lg bg-black bg-opacity-40">
                        <h4 class="text-cyan-400 font-bold mb-2">🤖 AI Analysis</h4>
                        <p class="text-gray-200 text-sm whitespace-pre-wrap">
                            ${result.ai_summary}
                        </p>
                    </div>
                `;
            }
        }


        // Update last analysis time
        document.getElementById('last-analysis').textContent = new Date().toLocaleTimeString();

        // Store current analysis
        this.currentAnalysis = result;
    }

    updateThreatMeter(score, riskLevel) {
        const scoreDisplay = document.getElementById('threat-score-display');
        const riskLevelDisplay = document.getElementById('risk-level');

        if (scoreDisplay) {
            anime({
                targets: { value: 0 },
                value: score,
                duration: 2000,
                easing: 'easeOutExpo',
                update: function(anim) {
                    scoreDisplay.textContent = Math.round(anim.animatables[0].target.value);
                }
            });
        }

        if (riskLevelDisplay) {
            riskLevelDisplay.textContent = riskLevel;
            riskLevelDisplay.className = `text-2xl font-bold mb-2 risk-${riskLevel.toLowerCase()}`;
        }
    }

    clearInput() {
        const emailInput = document.getElementById('email-input');
        const charCount = document.getElementById('char-count');

        if (emailInput) emailInput.value = '';
        if (charCount) charCount.textContent = '0';

        document.getElementById('analysis-results')?.classList.add('hidden');
        document.getElementById('threat-score-display').textContent = '0';
        document.getElementById('last-analysis').textContent = 'Never';

        this.updateThreatCircle(0);

        const risk = document.getElementById('risk-level');
        risk.textContent = 'Safe';
        risk.className = 'text-2xl font-bold mb-2 risk-safe';
    }

    async updateBackendSettings(updatedSettings) {
        const response = await fetch(`${this.backendUrl}/api/settings`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(updatedSettings)
        });

        if (!response.ok) {
            throw new Error('Failed to update backend settings');
        }
    }


    async blockSender() {
        if (!this.currentAnalysis) return;

        const emailInput = document.getElementById('email-input');
        const senderMatch = emailInput.value.match(/From:\s*([^\r\n]+)/i);
        const sender = senderMatch ? senderMatch[1].trim().toLowerCase() : null;

        if (!sender) {
            this.showNotification('No sender found to block', 'warning');
            return;
        }

        const settings = await fetch(`${this.backendUrl}/api/settings`).then(r => r.json());
        settings.blacklist = settings.blacklist || [];

        if (!settings.blacklist.includes(sender)) {
            settings.blacklist.push(sender);
            await this.updateBackendSettings(settings);
        }

        this.showNotification(`🚫 Sender blocked: ${sender}`, 'success');
    }


    async reportThreat() {
        if (this.currentAnalysis) {
            this.showNotification('Threat reported to security team', 'success');
            
            // In a real application, this would send to a security API
            console.log('Threat reported:', this.currentAnalysis);
        }
    }

    async whitelistSender() {
        if (!this.currentAnalysis) return;

        const emailInput = document.getElementById('email-input');
        const senderMatch = emailInput.value.match(/From:\s*([^\r\n]+)/i);
        const sender = senderMatch ? senderMatch[1].trim().toLowerCase() : null;

        if (!sender) {
            this.showNotification('No sender found to whitelist', 'warning');
            return;
        }

        const settings = await fetch(`${this.backendUrl}/api/settings`).then(r => r.json());
        settings.whitelist = settings.whitelist || [];

        if (!settings.whitelist.includes(sender)) {
            settings.whitelist.push(sender);
            await this.updateBackendSettings(settings);
        }

        this.showNotification(`✅ Sender whitelisted: ${sender}`, 'success');
    }


    populateRecentActivity() {
        const activities = [
            {
                type: 'threat',
                message: 'Phishing attempt blocked from suspicious@phishing-domain.com',
                time: '2 minutes ago',
                severity: 'high'
            },
            {
                type: 'scan',
                message: 'Email from ceo@legitimate-company.com analyzed - Clean',
                time: '5 minutes ago',
                severity: 'low'
            },
            {
                type: 'threat',
                message: 'Malware detected in attachment from unknown sender',
                time: '12 minutes ago',
                severity: 'critical'
            },
            {
                type: 'update',
                message: 'AI threat database updated with 247 new signatures',
                time: '1 hour ago',
                severity: 'info'
            },
            {
                type: 'scan',
                message: 'Bulk email campaign analyzed - 3% spam rate',
                time: '2 hours ago',
                severity: 'low'
            }
        ];

        const container = document.getElementById('recent-activity');
        if (!container) return;

        container.innerHTML = '';
        activities.forEach(activity => {
            const item = document.createElement('div');
            item.className = 'threat-item p-4 rounded-lg flex items-center justify-between';
            
            const typeIcons = {
                threat: '🚨',
                scan: '🔍',
                update: '🔄'
            };

            const severityColors = {
                critical: 'text-red-400',
                high: 'text-orange-400',
                medium: 'text-yellow-400',
                low: 'text-green-400',
                info: 'text-blue-400'
            };

            item.innerHTML = `
                <div class="flex items-center space-x-3">
                    <span class="text-xl">${typeIcons[activity.type] || '📧'}</span>
                    <div>
                        <div class="text-white font-medium text-sm">${activity.message}</div>
                        <div class="text-gray-400 text-xs">${activity.time}</div>
                    </div>
                </div>
                <div class="text-right">
                    <div class="${severityColors[activity.severity]} text-xs font-medium capitalize">${activity.severity}</div>
                </div>
            `;
            
            container.appendChild(item);
        });
    }

    startRealTimeUpdates() {
        // Simulate real-time threat counter updates
        setInterval(() => {
            const threatCounter = document.querySelector('.text-red-400');
            if (threatCounter && Math.random() < 0.1) {
                const currentCount = parseInt(threatCounter.textContent.match(/\d+/)[0]);
                const newCount = currentCount + Math.floor(Math.random() * 3);
                threatCounter.textContent = `${newCount} Active Threats`;
            }
        }, 10000);

        // Update stats periodically
        setInterval(() => {
            this.updateStats();
        }, 30000);
    }

    loadStatistics() {
        // Load statistics from backend or use defaults
        const stats = {
            emailsAnalyzed: 1247,
            threatsBlocked: 89,
            detectionRate: 99.2
        };

        // Try to get real stats from backend
        fetch(`${this.backendUrl}/api/threat-intelligence`)
            .then(response => response.json())
            .then(data => {
                stats.emailsAnalyzed = data.total_threats_analyzed || 1247;
                stats.threatsBlocked = Object.values(data.top_threat_types || {}).reduce((a, b) => a + b, 0) || 89;
                stats.detectionRate = data.detection_accuracy || 99.2;
            })
            .catch(() => {
                // Use default stats if backend not available
            })
            .finally(() => {
                this.updateStatisticsDisplay(stats);
            });
    }

    updateStatisticsDisplay(stats) {
        const emailsAnalyzed = document.getElementById('emails-analyzed');
        const threatsBlocked = document.getElementById('threats-blocked');
        const detectionRate = document.getElementById('detection-rate');

        if (emailsAnalyzed) {
            anime({
                targets: { value: 0 },
                value: stats.emailsAnalyzed,
                duration: 2000,
                easing: 'easeOutExpo',
                update: function(anim) {
                    emailsAnalyzed.textContent = Math.floor(anim.animatables[0].target.value).toLocaleString();
                }
            });
        }

        if (threatsBlocked) {
            anime({
                targets: { value: 0 },
                value: stats.threatsBlocked,
                duration: 2000,
                easing: 'easeOutExpo',
                update: function(anim) {
                    threatsBlocked.textContent = Math.floor(anim.animatables[0].target.value).toLocaleString();
                }
            });
        }

        if (detectionRate) {
            detectionRate.textContent = stats.detectionRate + '%';
        }
    }

    updateStats() {
        const stats = {
            emailsAnalyzed: Math.floor(Math.random() * 50) + 1200,
            threatsBlocked: Math.floor(Math.random() * 10) + 85,
            detectionRate: (99.0 + Math.random() * 0.5).toFixed(1)
        };

        this.updateStatisticsDisplay(stats);
    }

    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `fixed top-20 right-4 z-50 p-4 rounded-lg border transition-all duration-300 ${
            type === 'success' ? 'bg-green-900 border-green-400 text-green-100' :
            type === 'warning' ? 'bg-amber-900 border-amber-400 text-amber-100' :
            type === 'error' ? 'bg-red-900 border-red-400 text-red-100' :
            'bg-blue-900 border-blue-400 text-blue-100'
        }`;
        notification.textContent = message;
        
        document.body.appendChild(notification);
        
        // Animate in
        anime({
            targets: notification,
            opacity: [0, 1],
            translateX: [100, 0],
            duration: 300,
            easing: 'easeOutExpo'
        });
        
        // Remove after delay
        setTimeout(() => {
            anime({
                targets: notification,
                opacity: [1, 0],
                translateX: [0, 100],
                duration: 300,
                easing: 'easeOutExpo',
                complete: () => {
                    if (notification.parentNode) {
                        notification.parentNode.removeChild(notification);
                    }
                }
            });
        }, 3000);
    }
}

// Global functions for HTML onclick events
function scrollToAnalyzer() {
    const analyzer = document.getElementById('email-analyzer');
    if (analyzer) {
        analyzer.scrollIntoView({ behavior: 'smooth' });
    }
}
window.updateThreatCircle = function (score) {

    const circle = document.querySelector('.threat-score');
    const deg = Math.min(360, score * 3.6);

    let color = '#10b981';
    if (score > 70) color = '#991b1b';
    else if (score > 50) color = '#dc2626';
    else if (score > 30) color = '#f59e0b';

    circle.style.background = `conic-gradient(${color} ${deg}deg, #1f2937 ${deg}deg)`;
}


// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.spamShield = new SpamShield();
    
    // Add cursor trail effect
    document.addEventListener('mousemove', (e) => {
        if (Math.random() < 0.1) {
            const trail = document.createElement('div');
            trail.style.position = 'fixed';
            trail.style.left = e.clientX + 'px';
            trail.style.top = e.clientY + 'px';
            trail.style.width = '2px';
            trail.style.height = '2px';
            trail.style.background = '#00d4ff';
            trail.style.borderRadius = '50%';
            trail.style.pointerEvents = 'none';
            trail.style.zIndex = '9999';
            trail.style.opacity = '0.8';
            
            document.body.appendChild(trail);
            
            anime({
                targets: trail,
                scale: [1, 0],
                opacity: [0.8, 0],
                duration: 1000,
                easing: 'easeOutExpo',
                complete: () => {
                    if (trail.parentNode) {
                        trail.parentNode.removeChild(trail);
                    }
                }
            });
        }
    });
});