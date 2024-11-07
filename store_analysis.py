# store_analysis.py
import sqlite3

def store_analysis(email_content, is_phishing, confidence, reasoning):
    # Store analysis results in a SQLite database
    conn = sqlite3.connect("email_analysis.db")  # Connect to the database
    c = conn.cursor()
    # Create table with 'reasoning' and 'timestamp' fields to match the schema
    c.execute('''CREATE TABLE IF NOT EXISTS analysis
                 (email TEXT, is_phishing BOOLEAN, confidence REAL, reasoning TEXT,
                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    # Insert data into the analysis table
    c.execute("INSERT INTO analysis (email, is_phishing, confidence, reasoning) VALUES (?, ?, ?, ?)",
              (email_content, is_phishing, confidence, reasoning))
    conn.commit()
    conn.close()
