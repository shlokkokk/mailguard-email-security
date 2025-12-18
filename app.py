#!/usr/bin/env python3
"""
AI Spam Shield - Email Security Backend
A professional email threat detection system with deterministic analysis
"""
import os
from openai import OpenAI
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import re
import json
import hashlib
from datetime import datetime
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# from urllib.parse import urlparse
# import ipaddress

# AI Integration Placeholder - Add your API key here
# For OpenAI:
# import openai
# openai.api_key = "your-api-key-here"

# For Gemini:
# import google.generativeai as genai
# genai.configure(api_key="your-api-key-here")

app = Flask(__name__, static_folder='.', static_url_path='')

CORS(app, resources={
    r"/api/*": {
        "origins": [
            "http://localhost",
            "http://127.0.0.1",
            "http://localhost:5500"
        ]
    }
})


class EmailThreatAnalyzer:
    """
    Deterministic email threat analyzer
    Uses rule-based detection with consistent scoring
    """
    
    def __init__(self):
        self.setup_detection_rules()
        
    def setup_detection_rules(self):
        """Initialize detection patterns and rules"""
        
        # Phishing keywords - urgency and authority triggers
        self.phishing_keywords = [
            'urgent', 'immediate', 'asap', 'verify', 'confirm', 'validate',
            'suspended', 'locked', 'security breach', 'unauthorized access',
            'account compromised', 'click here', 'verify now', 'act immediately',
            'limited time', 'expires soon', 'final notice', 'legal action',
            'irs', 'tax', 'government', 'bank', 'paypal', 'amazon', 'microsoft',
            'apple', 'google', 'facebook', 'netflix', 'your account'
        ]
        
        # Scam indicators - financial and emotional manipulation
        self.scam_keywords = [
            'wire transfer', 'send money', 'bitcoin', 'cryptocurrency', 'investment',
            'guaranteed return', 'no risk', 'get rich', 'lottery winner', 'inheritance',
            'prince', 'nigerian', 'million dollars', 'free money', 'cash prize',
            'business opportunity', 'secret method', 'exclusive offer', 'limited spots',
            'act now', 'dont miss out', 'once in lifetime'
        ]
        
        # Spam indicators - promotional and marketing language
        self.spam_keywords = [
            'free', 'cheap', 'discount', 'sale', 'offer', 'promotion', 'advertisement',
            'buy now', 'order today', 'limited time offer', 'special price',
            'unsubscribe', 'opt-out', 'marketing', 'promotional', 'commercial',
            'viagra', 'cialis', 'weight loss', 'make money fast', 'work from home'
        ]   

        
        # Social engineering patterns
        self.social_patterns = [
            r'ceo.*wire.*transfer', r'urgent.*payment', r'confidential.*request',
            r'dont.*tell.*anyone', r'secret.*project', r'executive.*request'
        ]
        
        # Suspicious file extensions
        # Spam indicators - promotional and marketing language
        self.dangerous_extensions = [
            'exe', 'scr', 'bat', 'cmd', 'com', 'pif', 'jar', 'vbs', 'js',
            'zip', 'rar', '7z', 'tar', 'iso', 'img', 'dmg',
            'html', 'htm', 'mht', 'pdf', 'doc', 'docx', 'xls', 'xlsx'
        ]

        
        # Suspicious TLDs
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.click', '.link', '.download',
            '.work', '.party', '.racing', '.date', '.loan', '.win', '.accountant'
        ]
        
        # Shortened URL services
        self.url_shorteners = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'buff.ly',
            'short.link', 'is.gd', 'v.gd', 'cutt.ly', 'rebrand.ly'
        ]
    def get_settings(self):
        """Load settings from local JSON (fallback safe defaults)"""
        try:
            with open("settings.json", "r") as f:
                return json.load(f)
        except:
            return {
                "sensitivity": 75,
                "whitelist": [],
                "blacklist": []
            }
    
    def get_sensitivity(self):
        try:
            with open("settings.json", "r") as f:
                return json.load(f).get("sensitivity", 75)
        except:
            return 75

    
    def analyze_email(self, email_content):
        """
        Main analysis function - returns deterministic threat assessment
        """
        # Generate hash for consistent results
        email_hash = hashlib.md5(email_content.encode()).hexdigest()
        
        # Parse email components
        parsed = self.parse_email(email_content)

        # Load user settings
        settings = self.get_settings()
        sender = parsed.get("sender", "").lower()

        # Whitelist / Blacklist enforcement
        if sender in settings.get("whitelist", []):
            return self.safe_result("Sender is whitelisted")

        if sender in settings.get("blacklist", []):
            return self.blocked_result("Sender is blacklisted")
        
        # Calculate individual threat scores
        phishing_score = self.calculate_phishing_score(parsed)
        scam_score = self.calculate_scam_score(parsed)
        spam_score = self.calculate_spam_score(parsed)
        social_score = self.calculate_social_score(parsed)

        """
        # Apply sensitivity multiplier
        sensitivity = settings.get("sensitivity", 75)
        multiplier = sensitivity / 75

        phishing_score = min(int(phishing_score * multiplier), 100)
        scam_score = min(int(scam_score * multiplier), 100)
        spam_score = min(int(spam_score * multiplier), 100)
        social_score = min(int(social_score * multiplier), 100)
        """

        # Calculate overall threat score
        overall_score = max(phishing_score, scam_score, spam_score, social_score)

        # 🔥 APPLY USER SENSITIVITY (REAL FIX)
        sensitivity = self.get_sensitivity()
        overall_score = min(100, int(overall_score * (sensitivity / 75)))

        
        # Generate detailed explanation
        explanation = self.generate_explanation(parsed, {
            'phishing': phishing_score,
            'scam': scam_score,
            'spam': spam_score,
            'social': social_score
        })
        
        # Get AI-enhanced summary (optional)
        ai_summary = self.get_ai_summary(parsed, overall_score) if self.ai_available() else None
        
        return {
            'hash': email_hash,
            'timestamp': datetime.now().isoformat(),
            'overall_score': overall_score,
            'risk_level': self.get_risk_level(overall_score),
            'detailed_scores': {
                'phishing': phishing_score,
                'scam': scam_score,
                'spam': spam_score,
                'social_engineering': social_score
            },
            'explanation': explanation,
            'ai_summary': ai_summary,
            'indicators': self.extract_indicators(parsed)
        }
    
    def parse_email(self, content):
        """Parse email into components"""
        parsed = {
            'subject': '',
            'sender': '',
            'body': content,
            'urls': [],
            'attachments': [],
            'headers': {}
        }
        
        # Extract URLs
        url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w .?&%=;-]*'
        parsed['urls'] = re.findall(url_pattern, content, re.IGNORECASE)
        
        # Extract potential attachments
        attachment_pattern = r'\.(exe|scr|bat|cmd|com|pif|jar|vbs|js|zip|rar|7z|iso|img|dmg|html|htm|mht|pdf|doc|docx|xls|xlsx)'
        parsed['attachments'] = re.findall(attachment_pattern, content, re.IGNORECASE)

        # Attempt to extract sender email
        sender_match = re.search(
            r'^From:\s*([^\r\n]+)$',
            content,
            re.IGNORECASE | re.MULTILINE
        )

        if sender_match:
            parsed['sender'] = sender_match.group(1).strip().lower()


        
        return parsed
    
    def calculate_phishing_score(self, parsed):
        """Calculate phishing threat score (0-100)"""
        score = 0
        content_lower = parsed['body'].lower()
        
        # Check for phishing keywords
        for keyword in self.phishing_keywords:
            if keyword in content_lower:
                score += 3  # Each keyword adds 3 points
        
        # Check for brand impersonation
        brands = ['paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook', 'netflix', 'irs']
        for brand in brands:
            if brand in content_lower:
                score += 12
        
        # Check for urgency indicators
        urgency_words = ['urgent', 'immediate', 'asap', 'now', 'quickly']
        for word in urgency_words:
            if word in content_lower:
                score += 2
        
        # Check for suspicious URLs
        for url in parsed['urls']:
            url_lower = url.lower()
            # IP-based URLs
            if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url_lower):
                score += 30
            # Suspicious TLDs
            for tld in self.suspicious_tlds:
                if url_lower.endswith(tld):
                    score += 10
            # URL shorteners
            for shortener in self.url_shorteners:
                if shortener in url_lower:
                    score += 8
        
        return min(score, 100)  # Cap at 100
    
    def calculate_scam_score(self, parsed):
        """Calculate scam threat score (0-100)"""
        score = 0
        content_lower = parsed['body'].lower()
        
        # Check for scam keywords
        for keyword in self.scam_keywords:
            if keyword in content_lower:
                score += 4
        
        # Check for financial requests
        financial_terms = ['wire transfer', 'send money', 'bank account', 'routing number']
        for term in financial_terms:
            if term in content_lower:
                score += 8
        
        # Check for cryptocurrency mentions
        crypto_terms = ['bitcoin', 'cryptocurrency', 'btc', 'eth', 'wallet address']
        for term in crypto_terms:
            if term in content_lower:
                score += 6
        
        # Check for lottery/inheritance scams
        if any(term in content_lower for term in ['lottery', 'inheritance', 'winner', 'prince']):
            score += 12
        
        return min(score, 100)
    
    def calculate_spam_score(self, parsed):
        """Calculate spam threat score (0-100)"""
        score = 0
        content_lower = parsed['body'].lower()
        
        # Check for spam keywords
        for keyword in self.spam_keywords:
            if keyword in content_lower:
                score += 2
        
        # Check for promotional language
        promo_words = ['buy now', 'order today', 'limited time', 'special offer']
        for word in promo_words:
            if word in content_lower:
                score += 5
        
        # Check for unsubscribe links (common in spam)
        if 'unsubscribe' in content_lower or 'opt-out' in content_lower:
            score += 10
        
        # Check for excessive capitalization
        body_len = max(len(parsed['body']), 1)
        caps_ratio = sum(1 for c in parsed['body'] if c.isupper()) / body_len

        if caps_ratio > 0.3:  # More than 30% caps
            score += 8
        
        return min(score, 100)
    
    def calculate_social_score(self, parsed):
        """Calculate social engineering threat score (0-100)"""
        score = 0
        content_lower = parsed['body'].lower()
        
        # Check for social engineering patterns
        for pattern in self.social_patterns:
            if re.search(pattern, content_lower):
                score += 15
        
        # Check for authority impersonation
        authority_terms = ['ceo', 'president', 'director', 'manager', 'boss']
        for term in authority_terms:
            if term in content_lower:
                score += 8
        
        # Check for confidentiality requests
        if any(term in content_lower for term in ['confidential', 'secret', 'private', 'dont tell']):
            score += 12
        
        # Check for urgency combined with authority
        if any(auth in content_lower for auth in authority_terms) and \
           any(urg in content_lower for urg in ['urgent', 'immediate', 'asap']):
            score += 20
        
        return min(score, 100)
    
    def generate_explanation(self, parsed, scores):
        """Generate detailed explanation of threat assessment"""
        explanations = []
        
        # Phishing explanation
        if scores['phishing'] > 0:
            if scores['phishing'] > 70:
                explanations.append(f"🎣 HIGH PHISHING RISK ({scores['phishing']}%): Contains multiple phishing indicators including urgency language, brand impersonation, or suspicious URLs.")
            elif scores['phishing'] > 40:
                explanations.append(f"🎣 MODERATE PHISHING RISK ({scores['phishing']}%): Contains some phishing indicators that warrant caution.")
        
        # Scam explanation
        if scores['scam'] > 0:
            if scores['scam'] > 70:
                explanations.append(f"💰 HIGH SCAM RISK ({scores['scam']}%): Contains financial manipulation language, cryptocurrency requests, or lottery/inheritance scams.")
            elif scores['scam'] > 40:
                explanations.append(f"💰 MODERATE SCAM RISK ({scores['scam']}%): Contains some suspicious financial or investment language.")
        
        # Spam explanation
        if scores['spam'] > 0:
            if scores['spam'] > 70:
                explanations.append(f"📧 HIGH SPAM RISK ({scores['spam']}%): Contains promotional language, marketing terms, or unsubscribe links typical of bulk email.")
            elif scores['spam'] > 40:
                explanations.append(f"📧 MODERATE SPAM RISK ({scores['spam']}%): Contains some promotional or marketing language.")
        
        # Social engineering explanation
        if scores['social'] > 0:
            if scores['social'] > 70:
                explanations.append(f"🎭 HIGH SOCIAL ENGINEERING RISK ({scores['social']}%): Contains authority impersonation, confidentiality requests, or business email compromise patterns.")
            elif scores['social'] > 40:
                explanations.append(f"🎭 MODERATE SOCIAL ENGINEERING RISK ({scores['social']}%): Contains some manipulation tactics or authority references.")
        
        # URL analysis
        suspicious_urls = []
        for url in parsed['urls']:
            url_lower = url.lower()
            if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url_lower):
                suspicious_urls.append(f"IP-based URL: {url}")
            for tld in self.suspicious_tlds:
                if url_lower.endswith(tld):
                    suspicious_urls.append(f"Suspicious TLD: {url}")
            for shortener in self.url_shorteners:
                if shortener in url_lower:
                    suspicious_urls.append(f"URL shortener: {url}")
        
        if suspicious_urls:
            explanations.append(f"🔗 SUSPICIOUS URLs DETECTED: {', '.join(suspicious_urls[:3])}")
        
        # Attachment analysis
        if parsed['attachments']:
            dangerous_attachments = [
                ext for ext in parsed['attachments']
                if ext.lower().lstrip('.') in self.dangerous_extensions
            ]

            if dangerous_attachments:
                explanations.append(f"📎 SUSPICIOUS ATTACHMENTS: {', '.join(set(dangerous_attachments))}")
        
        # Safe email explanation
        if not explanations:
            explanations.append("✅ EMAIL APPEARS SAFE: No significant threat indicators detected. Standard business communication.")
        
        return '\n\n'.join(explanations)
    
    def get_risk_level(self, score):
        """Convert threat score to risk level"""
        if score >= 80:
            return 'CRITICAL'
        elif score >= 60:
            return 'HIGH'
        elif score >= 40:
            return 'MEDIUM'
        elif score >= 20:
            return 'LOW'
        else:
            return 'SAFE'
    
    def extract_indicators(self, parsed):
        """Extract threat indicators for detailed analysis"""
        indicators = {
            'keywords_found': [],
            'suspicious_urls': [],
            'dangerous_attachments': [],
            'patterns_matched': []
        }
        
        content_lower = parsed['body'].lower()
        
        # Find keywords
        all_keywords = self.phishing_keywords + self.scam_keywords + self.spam_keywords
        indicators['keywords_found'] = [kw for kw in all_keywords if kw in content_lower]
        
        # Find suspicious URLs
        for url in parsed['urls']:
            url_lower = url.lower()
            if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url_lower):
                indicators['suspicious_urls'].append(f"IP-based: {url}")
            for tld in self.suspicious_tlds:
                if url_lower.endswith(tld):
                    indicators['suspicious_urls'].append(f"Suspicious TLD: {url}")
        
        # Find dangerous attachments
        if parsed['attachments']:
            indicators['dangerous_attachments'] = list(set(parsed['attachments']))
        
        return indicators
    
    def get_ai_summary(self, parsed, overall_score):
        # Only use AI for meaningful threats
        if overall_score < 40:
            return None

        try:
            prompt = f"""
You are a cybersecurity analyst.

Explain the risk of this email clearly and simply.
Do NOT invent new threats.
Only explain what is already detected.

Threat score: {overall_score}/100
Sender: {parsed.get('sender', 'Unknown')}
URLs: {parsed.get('urls', [])}
Attachments: {parsed.get('attachments', [])}

Email content:
{parsed.get('body', '')[:800]}
"""

            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "Explain email threats clearly and honestly."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=120
            )

            return response.choices[0].message.content.strip()

        except Exception as e:
            print("AI summary error:", e)
            return None

    
    def ai_available(self):
        """Check if AI integration is available"""
        # Check if AI API key is configured
        # return bool(openai.api_key)  # For OpenAI
        # return True  # For Gemini if configured
        return bool(os.getenv("OPENAI_API_KEY"))  # Default to False
    
    def safe_result(self, reason):
        return {
            'overall_score': 0,
            'risk_level': 'SAFE',
            'explanation': f"✅ TRUSTED EMAIL: {reason}",
            'detailed_scores': {
                'phishing': 0,
                'scam': 0,
                'spam': 0,
                'social_engineering': 0
            }
        }

    def blocked_result(self, reason):
        return {
            'overall_score': 100,
            'risk_level': 'CRITICAL',
            'explanation': f"🚫 BLOCKED EMAIL: {reason}",
            'detailed_scores': {
                'phishing': 100,
                'scam': 100,
                'spam': 100,
                'social_engineering': 100
            }
        }

# Initialize analyzer
analyzer = EmailThreatAnalyzer()

@app.route('/')
def index():
    """Serve the main application"""
    return send_from_directory('.', 'index.html')

@app.route('/api/analyze', methods=['POST'])
def analyze_email():
    """Email analysis endpoint"""
    try:
        data = request.get_json()
        email_content = data.get('email', '')
        
        if not email_content:
            return jsonify({'error': 'No email content provided'}), 400
        
        # Perform analysis
        result = analyzer.analyze_email(email_content)
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/threat-intelligence', methods=['GET'])
def threat_intelligence():
    """Threat intelligence endpoint with sample data"""
    sample_data = {
        'total_threats_analyzed': 15847,
        'detection_accuracy': 99.2,
        'false_positive_rate': 0.8,
        'top_threat_types': {
            'phishing': 45,
            'scam': 25,
            'spam': 20,
            'social_engineering': 10
        },
        'weekly_trend': [
            {'date': '2024-01-01', 'threats': 234},
            {'date': '2024-01-02', 'threats': 267},
            {'date': '2024-01-03', 'threats': 198},
            {'date': '2024-01-04', 'threats': 312},
            {'date': '2024-01-05', 'threats': 289},
            {'date': '2024-01-06', 'threats': 156},
            {'date': '2024-01-07', 'threats': 278}
        ],
        'geographic_distribution': {
            'United States': 35,
            'China': 20,
            'Russia': 15,
            'Nigeria': 12,
            'India': 8,
            'Brazil': 6,
            'Other': 4
        },
        'sample_threats': [
            {
                'id': 'THR-2024-001',
                'type': 'Phishing',
                'severity': 'High',
                'description': 'Fake banking notification requesting credential verification',
                'first_seen': '2024-01-15',
                'status': 'Active'
            },
            {
                'id': 'THR-2024-002', 
                'type': 'Ransomware',
                'severity': 'Critical',
                'description': 'Email attachment containing LockBit ransomware variant',
                'first_seen': '2024-01-14',
                'status': 'Mitigated'
            },
            {
                'id': 'THR-2024-003',
                'type': 'Business Email Compromise',
                'severity': 'High',
                'description': 'CEO impersonation requesting wire transfer',
                'first_seen': '2024-01-13',
                'status': 'Active'
            }
        ]
    }
    
    return jsonify(sample_data)

@app.route('/api/settings', methods=['GET', 'POST'])
def settings():
    if request.method == 'GET':
        try:
            with open("settings.json", "r") as f:
                return jsonify(json.load(f))
        except:
            # fallback defaults if file missing
            return jsonify({
                "sensitivity": 75,
                "deepAnalysis": True,
                "behavioralAnalysis": True,
                "linkSandboxing": True,
                "criticalAlerts": True,
                "highAlerts": True,
                "dailySummary": False,
                "aiUpdates": True,
                "weeklyReports": True,
                "emailNotifications": True,
                "pushNotifications": False,
                "smsNotifications": False,
                "analytics": True,
                "contentAnalysis": True,
                "metadataCollection": True,
                "whitelist": [],
                "blacklist": []
            })
    elif request.method == 'POST':
        data = request.get_json()
        try:
            with open("settings.json", "w") as f:
                json.dump(data, f, indent=2)
            return jsonify({'status': 'success', 'message': 'Settings saved'})
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500

if __name__ == '__main__':
    print("Starting AI Spam Shield backend server...")
    print("Server running on http://localhost:5000")
    print("Add your AI API key in app.py to enable AI-enhanced explanations")
    app.run(debug=True, host='0.0.0.0', port=5000)