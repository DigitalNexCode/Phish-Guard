import sqlite3

# get_analysis_history.py
def get_analysis_history():
    conn = sqlite3.connect("email_analysis.db")
    c = conn.cursor()
    c.execute("SELECT * FROM analysis")
    return c.fetchall()
