import os
import subprocess
import hashlib
import sqlite3
import base64
import logging

# Vulnerability 1: Insecure use of os.system()
def run_command(command):
    os.system(command)  # Vulnerable to command injection if input is not sanitized

# Vulnerability 2: Hardcoded credentials
def login_user(username, password):
    if username == 'admin' and password == 'admin123':  # Hardcoded credentials
        return True
    else:
        return False

# Vulnerability 3: Use of weak hashing algorithm (MD5)
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # MD5 is weak and should not be used

# Vulnerability 4: SQL Injection vulnerability
def get_user_data(user_id):
    conn = sqlite3.connect('users.db')  # Assumes database is SQLite
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE user_id = {user_id};"  # Vulnerable to SQL Injection
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    return result

# Vulnerability 5: Insecure deserialization
def deserialize_data(data):
    return pickle.loads(data)  # Using pickle is dangerous if data is not trusted

# Vulnerability 6: Insecure file handling (no sanitization)
def upload_file(file):
    with open(f'/uploads/{file.filename}', 'wb') as f:
        f.write(file.read())  # No checks, could upload malicious files

# Vulnerability 7: Insecure logging (logs sensitive info)
def log_user_activity(username):
    logging.basicConfig(filename='user_activity.log', level=logging.DEBUG)
    logging.debug(f"User {username} logged in with IP: {os.getenv('USER_IP')}")  # Logs sensitive info

# Vulnerability 8: Weak access control
def access_admin_panel(user):
    if user == 'admin':
        print("Access granted to Admin Panel")  # No role-based access control, easy privilege escalation

# Technical Debt: Inconsistent coding style (indentation and variable names)
def get_data_from_api():
  url = 'http://api.example.com/data'
  response = requests.get(url)
  if response.status_code == 200:
   return response.json()
  else:
   return None

# Technical Debt: No exception handling
def connect_to_database():
    conn = sqlite3.connect('mydatabase.db')  # No try-except block for error handling
    return conn

# Technical Debt: Deprecated library (urllib)
def fetch_url_data(url):
    import urllib  # Deprecated library
    response = urllib.urlopen(url)  # urllib.urlopen is deprecated and insecure
    return response.read()

# Vulnerability 9: Insecure randomness (predictable random numbers)
def generate_session_token():
    return base64.b64encode(str(random.randint(1, 1000)).encode())  # Not using secure random number generation

# Vulnerability 10: Cross-site scripting (XSS) in the web framework
def render_user_input(input_string):
    return f"<div>{input_string}</div>"  # Vulnerable to XSS if input_string is user-controlled

# Function to trigger all vulnerabilities and technical debt
def main():
    user_input = input("Enter your username: ")
    user_pass = input("Enter your password: ")

    # Example of using vulnerable functions
    if login_user(user_input, user_pass):
        print("Login successful")
    else:
        print("Login failed")
    
    run_command("ls -l")

    hashed_password = hash_password('secret')
    print(f"Hashed password: {hashed_password}")
    
    data = get_user_data(1)
    print(f"User data: {data}")
    
    user = "admin"
    access_admin_panel(user)
    
    # Insecure file upload simulation
    class FakeFile:
        def __init__(self, filename):
            self.filename = filename

    file = FakeFile("test.exe")
    upload_file(file)

    log_user_activity(user_input)
    
    # Simulate XSS
    print(render_user_input('<script>alert("XSS")</script>'))

if __name__ == "__main__":
    main()
