# app.py
import streamlit as st
import sqlite3
from analyze_email import analyze_email, store_analysis
import re
from dotenv import load_dotenv
import os
import smtplib
from email.mime.text import MIMEText

# Load environment variables from .env file
load_dotenv()

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
        return True  # User created successfully
    except sqlite3.IntegrityError:
        return False  # User already exists
    finally:
        conn.close()

def login(username, password):
    conn = sqlite3.connect("user_data.db")
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
    user = c.fetchone()
    conn.close()
    return user is not None  # Return True if user exists

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
    domain = email.split('@')[-1]
    return re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain) is not None

# Placeholder for analyze_question function
def analyze_question(question, reasoning):
    # Here you would implement the logic to generate a response based on the question and reasoning.
    # For now, we'll return a simple response that indicates the question was understood.
    
    # Example logic (you can replace this with actual AI processing):
    if "reason" in question.lower():
        return f"The reasoning behind the analysis is: {reasoning}"
    else:
        return f"I'm sorry, but I can only provide information based on the reasoning: {reasoning}"

# Function to send a password reset email
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
    change_username_button = st.button("Change Username")

    if change_username_button:
        if new_username:
            # Update the username in the database
            if update_username(new_username):
                st.success("Username changed successfully!")
            else:
                st.error("Failed to change username. Please try again.")
        else:
            st.warning("Please enter a new username.")

    # Forgot Password
    st.write("### Forgot Password")
    email = st.text_input("Enter your email address for password reset")
    reset_password_button = st.button("Send Reset Link")

    if reset_password_button:
        if email:
            # Generate a reset link (you can implement your own logic here)
            reset_link = f"http://yourapp.com/reset_password?email={email}"  # Replace with your actual reset link
            if send_password_reset_email(email, reset_link):
                st.success("Password reset link sent to your email!")
            else:
                st.error("Failed to send password reset email. Please try again.")
        else:
            st.warning("Please enter your email address.")

    # Back to Main App Button
    if st.button("Back to Main App"):
        st.session_state.page = 'app'  # Navigate back to the main app page

def main():
    init_db()  # Initialize the database
    st.title("Email Phishing Analyzer")

    # User authentication
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False

    # Navigation between login, registration, and account management
    if 'page' not in st.session_state:
        st.session_state.page = 'login'  # Default page is login

    if st.session_state.page == 'login':
        login_page()
    elif st.session_state.page == 'register':
        register_page()
    elif st.session_state.page == 'account':
        account_page()  # Navigate to the account management page
    elif st.session_state.page == 'app':
        app_page()

def login_page():
    st.subheader("Login")

    # Login form
    login_form = st.form(key='login_form')
    username = login_form.text_input("Username")
    password = login_form.text_input("Password", type='password')
    login_button = login_form.form_submit_button("Login")

    if login_button:
        if login(username, password):
            st.session_state.logged_in = True
            st.session_state.page = 'app'  # Navigate to the app page
            st.success("Logged in successfully!")
        else:
            st.error("Invalid username or password.")

    if st.button("Register"):
        st.session_state.page = 'register'  # Navigate to the registration page

def register_page():
    st.subheader("Register")

    # Signup form
    signup_form = st.form(key='signup_form')
    new_username = signup_form.text_input("New Username")
    new_password = signup_form.text_input("New Password", type='password')
    signup_button = signup_form.form_submit_button("Signup")

    if signup_button:
        if signup(new_username, new_password):
            st.success("User created successfully! You can now log in.")
            st.session_state.page = 'login'  # Navigate back to the login page
        else:
            st.error("Username already exists.")

    if st.button("Back to Login"):
        st.session_state.page = 'login'  # Navigate back to the login page

def app_page():
    st.subheader("Email Phishing Analyzer - Main App")

    # Main application logic after login
    gemini_api_key = st.sidebar.text_input("Enter GEMINI API Key:", type="password")
    
    email_address = st.text_input("Enter the sender's email address:")
    email_content = st.text_area("Enter email content to analyze:", height=200)
    
    token_count = len(email_content.split())
    st.sidebar.write(f"Token Calculation: {token_count} tokens used")
    
    result = None  # Initialize result to None

    if st.button("Analyze"):
        if not email_address or not email_content:
            st.warning("Please enter both the email address and content to analyze.")
            return
        
        if not is_valid_email(email_address):
            st.warning("Please enter a valid email address.")
            return
            
        with st.spinner("Analyzing email..."):
            result = analyze_email(email_content)
            
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
    st.subheader("Ask Questions About the Email")
    
    question_container = st.container()
    
    with question_container:
        question = st.text_input("What would you like to know about the email?", key="question_input")
        submit_button = st.button("Submit Question", key="submit_question")

    if submit_button:
        if question:
            if result is not None:  # Check if result has been assigned
                response = analyze_question(question, result['reasoning'])  # Pass reasoning to the function
                st.write(f"**AI Response:** {response}")
                
                # Calculate token usage for the API call
                token_usage = len(question.split()) + len(result['reasoning'].split())
                st.write(f"**API Token Usage:** {token_usage} tokens used")
                
            else:
                # Retrieve the most recent analysis from the database for reasoning
                history = get_analysis_history()
                if history:
                    latest_record = history[0]  # Get the most recent record
                    reasoning = latest_record[3]  # Assuming reasoning is in the 4th column
                    response = analyze_question(question, reasoning)  # Use the latest reasoning
                    st.write(f"**AI Response:** {response}")
                    
                    # Calculate token usage for the API call
                    token_usage = len(question.split()) + len(reasoning.split())
                    st.write(f"**API Token Usage:** {token_usage} tokens used")
                else:
                    st.warning("No previous analysis found. Please analyze an email first.")
        else:
            st.warning("Please enter a question.")

    # Logout button
    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.page = 'login'  # Navigate back to the login page
        st.success("You have been logged out.")

    if st.sidebar.button("Account Management"):
        st.session_state.page = 'account'  # Navigate to the account management page

if __name__ == "__main__":
    main()