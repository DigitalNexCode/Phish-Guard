# analyze_email.py
import requests
import json
import streamlit as st
import sqlite3
import re
from dotenv import load_dotenv
import os

def clean_json_response(text):
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        if "```json" in text:
            text = text.split("```json")[1]
        elif "```" in text:
            text = text.split("```")[0]
        cleaned_text = text.strip()
        return json.loads(cleaned_text)

def extract_urls(text):
    url_pattern = r'https?://[^\s]+'
    return re.findall(url_pattern, text)

def is_suspicious_url(url):
    suspicious_keywords = ['login', 'secure', 'update', 'verify', 'account', 'confirm']
    return any(keyword in url.lower() for keyword in suspicious_keywords)

def analyze_email(email_content):
    api_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"
    api_key = os.getenv('GEMINI_API_KEY')
    
    if not api_key:
        st.error("API key not found. Please enter your GEMINI API key in the sidebar.")
        return {"is_phishing": False, "confidence": 0.0, "reasoning": "API key missing"}
    
    url_with_key = f"{api_url}?key={api_key}"

    headers = {
        "Content-Type": "application/json"
    }

    prompt = f"""
    Analyze this email for signs of phishing and respond with only a JSON object in this exact format:
    {{
        "is_phishing": true/false,
        "confidence": 0.0-1.0,
        "reasoning": "your detailed analysis here"
    }}
    Do not include any other text or markdown formatting.

    Email to analyze:
    {email_content}
    """

    payload = {
        "contents": [{
            "parts": [{"text": prompt}]
        }],
        "generationConfig": {
            "temperature": 0.1,
            "topK": 32,
            "topP": 1
        }
    }

    try:
        response = requests.post(url_with_key, headers=headers, json=payload)
        
        if response.status_code != 200:
            st.error(f"API Error: {response.status_code}")
            return {"is_phishing": False, "confidence": 0.0, "reasoning": "API error"}

        result = response.json()
        
        try:
            if 'candidates' in result and result['candidates']:
                text_response = result['candidates'][0]['content']['parts'][0]['text']
                analysis = clean_json_response(text_response)
                
                urls = extract_urls(email_content)
                suspicious_urls = [url for url in urls if is_suspicious_url(url)]
                
                is_phishing = analysis.get("is_phishing", False) or bool(suspicious_urls)
                confidence = min(analysis.get("confidence", 0.0) + (0.5 * len(suspicious_urls)), 1.0)
                
                return {
                    "is_phishing": is_phishing,
                    "confidence": confidence,
                    "reasoning": analysis.get("reasoning", "No reasoning provided") + 
                                (f" Found suspicious URLs: {suspicious_urls}" if suspicious_urls else "")
                }
            else:
                raise KeyError("No valid response from API")
            
        except (KeyError, json.JSONDecodeError) as e:
            st.error(f"Error parsing response: {e}")
            return fallback_analysis(email_content)

    except requests.exceptions.RequestException as e:
        st.error(f"API request failed: {e}")
        return {"is_phishing": False, "confidence": 0.0, "reasoning": str(e)}

def fallback_analysis(email_content):
    keywords = [
        'urgency', 'urgent', 'act now', 'important', 'last chance', 'limited time',
        'free', 'money', 'cash', 'earn money', 'income', '100% free', 'risk-free',
        'no fees', 'unsecured credit', 'multi-level marketing', 'mlm', 'best price',
        'incredible deal', 'save big', 'free gift', 'win big', 'click here', 'call now',
        'don\'t delete', 'congratulations', 'you won', 'free trial',
        'invoice', 'statement', 'payment required', 'account verification', 'action required',
        'verification needed', 'your account will be suspended', 'immediate response needed',
        'request for information', 'document attached', 'file shared with you',
        'new message from', 'important update regarding your account', 'you have a new notification'
    ]

    email_lower = email_content.lower()
    suspicious_count = sum(1 for keyword in keywords if keyword in email_lower)

    return {
        "is_phishing": suspicious_count >= 2,
        "confidence": min(suspicious_count / len(keywords), 1.0),
        "reasoning": f"Fallback analysis: Found {suspicious_count} suspicious keywords."
    }

def store_analysis(email_content, is_phishing, confidence, reasoning):
    try:
        conn = sqlite3.connect("email_analysis.db")
        c = conn.cursor()
        
        # Create table if it doesn't exist
        c.execute('''CREATE TABLE IF NOT EXISTS analysis
                     (email TEXT, is_phishing BOOLEAN, confidence REAL, reasoning TEXT,
                      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        
        # Store the analysis results
        c.execute("""INSERT INTO analysis 
                     (email, is_phishing, confidence, reasoning)
                     VALUES (?, ?, ?, ?)""",
                  (email_content, is_phishing, confidence, reasoning))
        
        conn.commit()
    except sqlite3.Error as e:
        st.error(f"Database error: {e}")
    finally:
        if 'conn' in locals():
            conn.close()