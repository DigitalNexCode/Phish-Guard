# database.py
import sqlite3
from datetime import datetime
from typing import Optional, Tuple, List
import logging

class DatabaseManager:
    def __init__(self, user_db="user_data.db", analysis_db="email_analysis.db"):
        self.user_db = user_db
        self.analysis_db = analysis_db
        self.setup_databases()
        
    def setup_databases(self):
        """Initialize both databases and create required tables"""
        # Setup user database
        try:
            with sqlite3.connect(self.user_db) as conn:
                c = conn.cursor()
                c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )''')
                conn.commit()
        except sqlite3.Error as e:
            logging.error(f"Error creating users table: {e}")
            
        # Setup analysis database
        try:
            with sqlite3.connect(self.analysis_db) as conn:
                c = conn.cursor()
                c.execute('''CREATE TABLE IF NOT EXISTS analysis (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    email TEXT NOT NULL,
                    is_phishing BOOLEAN NOT NULL,
                    confidence REAL NOT NULL,
                    reasoning TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )''')
                conn.commit()
        except sqlite3.Error as e:
            logging.error(f"Error creating analysis table: {e}")
    
    def check_credentials(self, username: str, password: str) -> Optional[int]:
        """Verify user credentials and return user_id if valid"""
        try:
            with sqlite3.connect(self.user_db) as conn:
                c = conn.cursor()
                c.execute("SELECT id FROM users WHERE username = ? AND password = ?", 
                         (username, password))
                result = c.fetchone()
                return result[0] if result else None
        except sqlite3.Error as e:
            logging.error(f"Error checking credentials: {e}")
            return None
    
    def register_user(self, username: str, password: str) -> bool:
        """Register a new user"""
        try:
            with sqlite3.connect(self.user_db) as conn:
                c = conn.cursor()
                c.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                         (username, password))
                conn.commit()
                return True
        except sqlite3.IntegrityError:
            return False  # Username already exists
        except sqlite3.Error as e:
            logging.error(f"Error registering user: {e}")
            return False
    
    def store_analysis(self, user_id: int, email_content: str, 
                      is_phishing: bool, confidence: float, 
                      reasoning: str) -> bool:
        """Store email analysis results"""
        try:
            with sqlite3.connect(self.analysis_db) as conn:
                c = conn.cursor()
                c.execute("""
                    INSERT INTO analysis (
                        user_id, email, is_phishing, confidence, reasoning
                    ) VALUES (?, ?, ?, ?, ?)
                """, (user_id, email_content, is_phishing, confidence, reasoning))
                conn.commit()
                return True
        except sqlite3.Error as e:
            logging.error(f"Error storing analysis: {e}")
            return False
    
    def get_user_analysis_history(self, user_id: int, limit: int = 10) -> List[Tuple]:
        """Retrieve analysis history for a specific user"""
        try:
            with sqlite3.connect(self.analysis_db) as conn:
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                c.execute("""
                    SELECT * FROM analysis 
                    WHERE user_id = ? 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                """, (user_id, limit))
                return [dict(row) for row in c.fetchall()]
        except sqlite3.Error as e:
            logging.error(f"Error retrieving analysis history: {e}")
            return []

# Create a global instance
db = DatabaseManager()