from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
import os
import requests
from datetime import datetime
import sqlite3
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# Get the absolute path to the templates folder
template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'templates'))

app = Flask(__name__, template_folder=template_dir)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(16))

# OpenRouter API configuration
OPENROUTER_API_KEY = os.environ.get('OPENROUTER_API_KEY')
OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"

# Database initialization
def init_db():
    conn = sqlite3.connect('chat_history.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  email TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL,
                  created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    
    # Conversations table (linked to users)
    c.execute('''CREATE TABLE IF NOT EXISTS conversations
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  role TEXT,
                  content TEXT,
                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                  model TEXT,
                  FOREIGN KEY (user_id) REFERENCES users(id))''')
    
    conn.commit()
    conn.close()

init_db()

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_conversation_history(user_id, limit=20):
    conn = sqlite3.connect('chat_history.db')
    c = conn.cursor()
    c.execute('''SELECT role, content FROM conversations 
                 WHERE user_id = ? 
                 ORDER BY timestamp DESC LIMIT ?''', (user_id, limit))
    messages = c.fetchall()
    conn.close()
    return [{"role": msg[0], "content": msg[1]} for msg in reversed(messages)]

def save_message(user_id, role, content, model):
    conn = sqlite3.connect('chat_history.db')
    c = conn.cursor()
    c.execute('''INSERT INTO conversations (user_id, role, content, model)
                 VALUES (?, ?, ?, ?)''', (user_id, role, content, model))
    conn.commit()
    conn.close()

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('chat_page'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('chat_page'))
    
    if request.method == 'POST':
        data = request.json
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        
        # Validation
        if not username or not email or not password:
            return jsonify({'success': False, 'error': 'All fields are required'}), 400
        
        if len(username) < 3:
            return jsonify({'success': False, 'error': 'Username must be at least 3 characters'}), 400
        
        if len(password) < 6:
            return jsonify({'success': False, 'error': 'Password must be at least 6 characters'}), 400
        
        try:
            conn = sqlite3.connect('chat_history.db')
            c = conn.cursor()
            
            # Check if username or email already exists
            c.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
            if c.fetchone():
                conn.close()
                return jsonify({'success': False, 'error': 'Username or email already exists'}), 400
            
            # Create user
            password_hash = generate_password_hash(password)
            c.execute('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                     (username, email, password_hash))
            conn.commit()
            user_id = c.lastrowid
            conn.close()
            
            # Log user in
            session['user_id'] = user_id
            session['username'] = username
            
            return jsonify({'success': True, 'redirect': url_for('chat_page')})
            
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('chat_page'))
    
    if request.method == 'POST':
        data = request.json
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({'success': False, 'error': 'All fields are required'}), 400
        
        try:
            conn = sqlite3.connect('chat_history.db')
            c = conn.cursor()
            c.execute('SELECT id, username, password_hash FROM users WHERE username = ? OR email = ?',
                     (username, username))
            user = c.fetchone()
            conn.close()
            
            if user and check_password_hash(user[2], password):
                session['user_id'] = user[0]
                session['username'] = user[1]
                return jsonify({'success': True, 'redirect': url_for('chat_page')})
            else:
                return jsonify({'success': False, 'error': 'Invalid username or password'}), 401
                
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/chat')
@login_required
def chat_page():
    return render_template('index.html', username=session.get('username'))

@app.route('/api/chat', methods=['POST'])
@login_required
def chat():
    try:
        data = request.json
        user_message = data.get('message', '')
        selected_model = data.get('model', 'google/gemini-2.0-flash-exp:free')
        
        if not user_message:
            return jsonify({'error': 'No message provided'}), 400
        
        if not OPENROUTER_API_KEY:
            return jsonify({'error': 'OpenRouter API key not configured'}), 500
        
        user_id = session.get('user_id')
        
        # Get conversation history
        history = get_conversation_history(user_id)
        
        # Add current message to history
        messages = history + [{"role": "user", "content": user_message}]
        
        # Fallback models if primary is rate-limited
        fallback_models = [
            selected_model,
            'google/gemini-2.0-flash-exp:free',
            'meta-llama/llama-3.1-8b-instruct:free',
            'mistralai/mistral-7b-instruct:free'
        ]
        
        # Try models in order until one works
        last_error = None
        for model in fallback_models:
            try:
                # Call OpenRouter API
                headers = {
                    "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": request.host_url,
                    "X-Title": "Personal AI Chat"
                }
                
                payload = {
                    "model": model,
                    "messages": messages
                }
                
                response = requests.post(OPENROUTER_API_URL, headers=headers, json=payload, timeout=30)
                
                if response.status_code == 200:
                    result = response.json()
                    assistant_message = result['choices'][0]['message']['content']
                    
                    # Save both messages to database
                    save_message(user_id, "user", user_message, model)
                    save_message(user_id, "assistant", assistant_message, model)
                    
                    # Inform user if fallback was used
                    model_note = ""
                    if model != selected_model:
                        model_note = f"\n\n_Note: Using {model} (selected model was rate-limited)_"
                    
                    return jsonify({
                        'response': assistant_message + model_note,
                        'model': model
                    })
                else:
                    # Store error and try next model
                    error_data = response.json()
                    last_error = error_data.get('error', {}).get('message', response.text)
                    continue
                    
            except requests.exceptions.Timeout:
                last_error = "Request timeout"
                continue
            except Exception as e:
                last_error = str(e)
                continue
        
        # All models failed
        return jsonify({'error': f'All models rate-limited or unavailable. Please try again in a few minutes or add credits to OpenRouter. Last error: {last_error}'}), 429
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/history')
@login_required
def get_history():
    user_id = session.get('user_id')
    history = get_conversation_history(user_id, limit=50)
    return jsonify({'history': history})

@app.route('/api/clear', methods=['POST'])
@login_required
def clear_history():
    user_id = session.get('user_id')
    conn = sqlite3.connect('chat_history.db')
    c = conn.cursor()
    c.execute('DELETE FROM conversations WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

# Health check endpoint for UptimeRobot
@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'timestamp': datetime.now().isoformat()})

# Error handlers
@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Page not found'}), 404

@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal server error', 'details': str(e)}), 500

# Test route to check if app is running
@app.route('/test')
def test():
    return '''
    <html>
        <body>
            <h1>App is running!</h1>
            <p>If you see this, the app is working.</p>
            <a href="/login">Go to Login</a>
        </body>
    </html>
    '''

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
