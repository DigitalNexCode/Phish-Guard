# app.py
import streamlit as st
import sqlite3
from analyze_email import analyze_email, store_analysis
import re
from dotenv import load_dotenv
import os
import smtplib
from email.mime.text import MIMEText
import requests

# Load environment variables from .env file
load_dotenv()

# Initialize session state for API key if it doesn't exist
if 'gemini_api_key' not in st.session_state:
    st.session_state.gemini_api_key = ''

# Database setup
def init_db():
    conn = sqlite3.connect("user_data.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY, password TEXT)''')
    conn.commit()
    conn.close()

def signup(username, password):
    conn = sqlite3.connect("user_data.db")
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def login(username, password):
    conn = sqlite3.connect("user_data.db")
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
    user = c.fetchone()
    conn.close()
    return user is not None

def get_analysis_history():
    try:
        conn = sqlite3.connect("email_analysis.db")
        c = conn.cursor()
        c.execute('''SELECT email, is_phishing, confidence, reasoning, timestamp 
                    FROM analysis ORDER BY timestamp DESC LIMIT 10''')
        return c.fetchall()
    except sqlite3.Error as e:
        st.error(f"Database error: {e}")
        return []
    finally:
        if 'conn' in locals():
            conn.close()

def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def analyze_question(question, reasoning):
    # First, summarize the reasoning
    summary_response = summarize_reasoning(reasoning)
    summarized_reasoning = summary_response.get("content", "Unable to summarize reasoning.")

    api_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"
    api_key = os.getenv('GEMINI_API_KEY')

    if not api_key:
        return {"content": "API key not found."}

    url_with_key = f"{api_url}?key={api_key}"

    prompt = f"""
    Based on the following summarized reasoning, answer the question:
    
    Summarized Reasoning: {summarized_reasoning}
    
    Question: {question}
    
    Provide a concise answer.
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

    headers = {
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(url_with_key, headers=headers, json=payload)

        if response.status_code != 200:
            return {"content": f"API Error: {response.status_code} - {response.text}"}

        result = response.json()
        print("API Response:", result)  # Log the full response for debugging

        if 'candidates' in result and result['candidates']:
            # Check for finishReason
            if result['candidates'][0].get('finishReason') == 'SAFETY':
                return {
                    "content": "The response was flagged for safety concerns. Please rephrase your question. "
                               "Try to avoid sensitive topics or controversial language. "
                               "For example, instead of asking about specific dangers, you might ask for general advice on email safety."
                }

            # Check if 'content' and 'parts' exist before accessing them
            if 'content' in result['candidates'][0] and 'parts' in result['candidates'][0]['content']:
                text_response = result['candidates'][0]['content']['parts'][0]['text']
                return {
                    "content": text_response.strip(),
                    "learning_points": [
                        "Phishing emails often use emotional manipulation.",
                        "Look for generic greetings and lack of personal details.",
                        "Be cautious of requests for private communication."
                    ]
                }
            else:
                return {"content": "No valid response structure from API."}
        else:
            return {"content": "No valid response from API."}

    except requests.exceptions.RequestException as err:
        return {"content": f"API request failed: {err}"}

def send_password_reset_email(email, reset_link):
    msg = MIMEText(f"Click the link to reset your password: {reset_link}")
    msg['Subject'] = 'Password Reset Request'
    msg['From'] = 'your_email@example.com'  # Replace with your email
    msg['To'] = email

    try:
        with smtplib.SMTP('smtp.example.com', 587) as server:  # Replace with your SMTP server
            server.starttls()
            server.login('your_email@example.com', 'your_password')  # Replace with your email and password
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

def account_page():
    st.subheader("Account Management")

    # Change Username
    st.write("### Change Username")
    new_username = st.text_input("New Username")
    if st.button("Change Username"):
        if new_username:
            st.warning("Username change functionality not implemented in this demo")
        else:
            st.warning("Please enter a new username.")

    # Forgot Password
    st.write("### Forgot Password")
    email = st.text_input("Enter your email address for password reset")
    if st.button("Send Reset Link"):
        if email and is_valid_email(email):
            reset_link = f"http://yourapp.com/reset_password?email={email}"
            if send_password_reset_email(email, reset_link):
                st.success("Password reset link sent to your email!")
            else:
                st.error("Failed to send password reset email. Please try again.")
        else:
            st.warning("Please enter a valid email address.")

    if st.button("Back to Main App"):
        st.session_state.page = 'app'

def get_latest_analysis():
    """Fetch the latest analysis from the database."""
    conn = sqlite3.connect("email_analysis.db")
    c = conn.cursor()
    c.execute("SELECT * FROM analysis ORDER BY timestamp DESC LIMIT 1")
    return c.fetchone()  # Returns the latest analysis record

def app_page():
    st.subheader("Email Phishing Analyzer - Main App")

    # Sidebar for API Key and Token Usage
    with st.sidebar:
        st.header("Configuration")
        api_key = st.text_input(
            "Enter GEMINI API Key:",
            type="password",
            value=st.session_state.gemini_api_key,
            key="api_key_input"
        )
        
        if api_key != st.session_state.gemini_api_key:
            st.session_state.gemini_api_key = api_key

        st.header("Token Usage")
        st.info("""
        Token calculation:
        - Each word counts as approximately 1 token
        - Special characters and numbers may count as additional tokens
        """)
        
        if 'total_tokens_used' not in st.session_state:
            st.session_state.total_tokens_used = 0
            
        st.metric("Total Tokens Used", st.session_state.total_tokens_used)

    # Main content area
    email_address = st.text_input("Enter the sender's email address:")
    email_content = st.text_area("Enter email content to analyze:", height=200)
    
    current_tokens = len(email_content.split())
    st.info(f"Current input uses approximately {current_tokens} tokens")

    result = None

    if st.button("Analyze"):
        if not st.session_state.gemini_api_key:
            st.error("Please enter your GEMINI API key in the sidebar first.")
            return
            
        if not email_address or not email_content:
            st.warning("Please enter both the email address and content to analyze.")
            return
        
        if not is_valid_email(email_address):
            st.warning("Please enter a valid email address.")
            return
            
        with st.spinner("Analyzing email..."):
            os.environ['GEMINI_API_KEY'] = st.session_state.gemini_api_key
            result = analyze_email(email_content)
            # Store the result in session state for later use
            st.session_state.latest_analysis = result
            st.session_state.total_tokens_used += current_tokens
            
            st.write("### Analysis Results")
            if result['is_phishing']:
                st.error(f"⚠️ Potential Phishing Detected!")
            else:
                st.success("✅ Email appears safe")
                
            st.write(f"Confidence: {result['confidence']:.2%}")
            st.write("### Analysis Reasoning")
            st.write(result['reasoning'])
            
            store_analysis(
                email_address,
                result['is_phishing'],
                result['confidence'],
                result['reasoning']
            )

    if st.button("Show Recent Analysis History"):
        st.write("### Recent Analysis History")
        history = get_analysis_history()
        for record in history:
            with st.expander(f"Analysis from {record[4]}"):
                st.write(f"**Email Content:** {record[0][:200]}...")
                st.write(f"**Phishing Detection:** {'Yes' if record[1] else 'No'}")
                st.write(f"**Confidence:** {record[2]:.2%}")
                st.write(f"**Reasoning:** {record[3]}")

    # Question-asking feature
    st.subheader("Ask Questions About the Analysis")
    question = st.text_input("What would you like to know about the email?")
    question_tokens = len(question.split())
    st.info(f"Question uses approximately {question_tokens} tokens")

    if st.button("Submit Question"):
        if question:
            # Fetch the latest analysis from the database
            latest_analysis = get_latest_analysis()
            if latest_analysis:
                reasoning = latest_analysis[3]  # Assuming reasoning is the 4th column
                response = analyze_question(question, reasoning)
                st.write(f"**Your Question:** {question}")
                st.write(f"**AI Response:** {response['content']}")
                response_tokens = len(response['content'].split())
                st.session_state.total_tokens_used += (question_tokens + response_tokens)
            else:
                st.warning("No analysis found in the database.")
        else:
            st.warning("Please enter a question.")

    # Logout and Account Management
    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.page = 'login'
        st.success("You have been logged out.")

    if st.sidebar.button("Account Management"):
        st.session_state.page = 'account'

def login_page():
    st.subheader("Login")
    login_form = st.form(key='login_form')
    username = login_form.text_input("Username")
    password = login_form.text_input("Password", type='password')
    submit = login_form.form_submit_button("Login")

    if submit:
        if login(username, password):
            st.session_state.logged_in = True
            st.session_state.page = 'app'
            st.success("Logged in successfully!")
        else:
            st.error("Invalid username or password.")

    if st.button("Register"):
        st.session_state.page = 'register'

def register_page():
    st.subheader("Register")
    signup_form = st.form(key='signup_form')
    new_username = signup_form.text_input("New Username")
    new_password = signup_form.text_input("New Password", type='password')
    submit = signup_form.form_submit_button("Sign Up")

    if submit:
        if signup(new_username, new_password):
            st.success("Registration successful! Please login.")
            st.session_state.page = 'login'
        else:
            st.error("Username already exists.")

    if st.button("Back to Login"):
        st.session_state.page = 'login'

def summarize_reasoning(reasoning):
    api_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"
    api_key = os.getenv('GEMINI_API_KEY')

    if not api_key:
        return {"content": "API key not found."}

    url_with_key = f"{api_url}?key={api_key}"

    prompt = f"Summarize the following reasoning:\n\n{reasoning}\n\nProvide a concise summary."

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

    headers = {
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(url_with_key, headers=headers, json=payload)

        if response.status_code != 200:
            return {"content": f"API Error: {response.status_code} - {response.text}"}

        result = response.json()
        print("API Response:", result)  # Log the full response for debugging

        if 'candidates' in result and result['candidates']:
            if 'content' in result['candidates'][0] and 'parts' in result['candidates'][0]['content']:
                text_response = result['candidates'][0]['content']['parts'][0]['text']
                return {"content": text_response.strip()}
            else:
                return {"content": "No valid response structure from API."}
        else:
            return {"content": "No valid response from API."}

    except requests.exceptions.RequestException as err:
        return {"content": f"API request failed: {err}"}

def main():
    st.title("Email Phishing Analyzer")
    
    # Initialize session state attributes
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    if 'page' not in st.session_state:
        st.session_state.page = 'login'  # Default page is login

    # User authentication and navigation
    if st.session_state.page == 'login':
        login_page()
    elif st.session_state.page == 'register':
        register_page()
    elif st.session_state.page == 'account':
        account_page()  # Navigate to the account management page
    elif st.session_state.page == 'app':
        app_page()  # Navigate to the main app page

if __name__ == "__main__":
    init_db()
    main()