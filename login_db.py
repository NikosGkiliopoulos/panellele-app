from flask import Flask, render_template, request, redirect, make_response, session, url_for, jsonify, flash
import sqlite3, hashlib, re
import smtplib, ssl
from email.mime.text import MIMEText
import smtplib, certifi
import uuid
import time, os
import stripe
from flask import jsonify
from datetime import datetime, timedelta
from dotenv import load_dotenv

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Needed for session handling

# --- Utility functions ---
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def get_db():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

def is_valid_password(password):
    return (len(password) >= 8 and
            re.search(r'[A-Z]', password) and
            re.search(r'[a-z]', password) and
            re.search(r'\d', password))

def send_reset_email(to_email, token):
    sender_email = "mpazmpaz21@gmail.com"
    app_password = os.getenv("EMAIL_APP_PASSWORD")
    subject = "Password Reset"
    body = f"Click here to reset your password: http://localhost:5000/reset-password/{token}"

    msg = MIMEText(body, "plain")
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = to_email

    context = ssl.create_default_context(cafile=certifi.where())
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
        server.login(sender_email, app_password)
        server.sendmail(sender_email, to_email, msg.as_string())

def get_user_by_id(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    return user

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# --- Routes ---
@app.route('/')
def index():
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # 🔐 Auto-login if session or cookie exists
    if 'username' in session:
        return redirect('/home')

    remembered = request.cookies.get('remembered_user')
    if remembered:
        session['username'] = remembered
        return redirect('/home')

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember = request.form.get('remember')

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()

        if result and result[0] == hash_password(password):
            session['username'] = username
            resp = make_response(redirect('/home'))
            if remember == 'on':
                resp.set_cookie('remembered_user', username, max_age=60 * 60 * 24 * 7)  # 1 week
            else:
                resp.set_cookie('remembered_user', '', expires=0)
            return resp
        else:
            # Instead of redirecting, you stay on the login page with an error message
            error_message = "❌ Invalid username or password."
            return render_template('login.html', error_message=error_message)

    return render_template('login.html', error_message=None)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    message = ""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        gender = request.form['gender']
        age = request.form['age']

        if not is_valid_password(password):
            message = "❌ Password must be at least 8 characters and include an uppercase letter, lowercase letter, and number."
        else:
            conn = get_db()
            cursor = conn.cursor()
            try:
                cursor.execute('''
                    INSERT INTO users (username, password, email, gender, age)
                    VALUES (?, ?, ?, ?, ?)
                ''', (username, hash_password(password), email, gender, age ))
                conn.commit()
                message = "✅ User registered successfully!"
            except sqlite3.IntegrityError:
                message = "⚠️ Username already taken."
            finally:
                conn.close()

    return render_template('signup.html', message=message)

@app.route('/home')
def home():
    if 'username' not in session:
        return redirect('/login')
    return render_template('home.html', username=session['username'])

@app.route('/logout')
def logout():
    session.pop('username', None)
    resp = make_response(redirect('/login'))
    resp.set_cookie('remembered_user', '', expires=0)
    return resp

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    message = ""
    user_email = None
    if request.method == 'POST':
        username = request.form['username']

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT email FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result:
            user_email = result['email']
            token = str(uuid.uuid4())
            expiration = int(time.time()) + 3600  # valid for 1 hour

            cursor.execute("UPDATE users SET reset_token = ?, token_expiration = ? WHERE username = ?",
                           (token, expiration, username))
            conn.commit()
            conn.close()

            send_reset_email(user_email, token)
            message = f"✅ Password reset email sent to {user_email}."
        else:
            message = "❌ No account found with that username."

    return render_template('forgot_password.html', message=message, email=user_email)

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    message = ""
    if request.method == 'POST':
        new_password = request.form['password']

        if not is_valid_password(new_password):
            message = "❌ Password must be at least 8 characters with uppercase, lowercase, and number."
        else:
            conn = get_db()
            cursor = conn.cursor()

            cursor.execute("SELECT username, token_expiration FROM users WHERE reset_token = ?", (token,))
            user = cursor.fetchone()

            if user and int(time.time()) < user['token_expiration']:
                hashed_pw = hash_password(new_password)
                cursor.execute('''
                    UPDATE users
                    SET password = ?, reset_token = NULL, token_expiration = NULL
                    WHERE reset_token = ?
                ''', (hashed_pw, token))
                conn.commit()
                conn.close()
                message = "✅ Password successfully reset. You can now log in."
                return render_template("reset_password.html", message=message, success=True)
            else:
                message = "❌ Invalid or expired token."
                conn.close()

    return render_template("reset_password.html", message=message, success=False)

@app.route('/economics_courses')
def economics_courses():
    if 'username' not in session:
        return redirect('/login')
    return render_template('economics_courses.html')

@app.route('/science_courses')
def science_courses():
    if 'username' not in session:
        return redirect('/login')
    return render_template('science_courses.html')

@app.route('/health_courses')
def health_courses():
    if 'username' not in session:
        return redirect('/login')
    return render_template('health_courses.html')

@app.route('/humanities_courses')
def humanities_courses():
    if 'username' not in session:
        return redirect('/login')
    return render_template('humanities_courses.html')

@app.route('/track/<track_name>')
def track_access(track_name):
    if 'username' not in session:
        return redirect('/login')

    column_map = {
        'science': 'has_science',
        'health': 'has_health',
        'economics': 'has_economics',
        'humanities': 'has_humanities'
    }

    expiry_map = {
        'science': 'science_expiry',
        'health': 'health_expiry',
        'economics': 'economics_expiry',
        'humanities': 'humanities_expiry'
    }

    if track_name not in column_map:
        return "Μη έγκυρο πεδίο", 404

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (session['username'],))
    user = cursor.fetchone()
    conn.close()

    access = user[column_map[track_name]]
    expiry = user[expiry_map[track_name]]

    if access and expiry:
        if datetime.strptime(expiry, '%Y-%m-%d') >= datetime.now():
            return redirect(f'/{track_name}_courses')

    return render_template('payment.html', track=track_name)

load_dotenv()  # Φορτώνει τις μεταβλητές από το .env αρχείο
stripe.api_key =os.getenv("STRIPE_TEST_KEY")

@app.route('/payment/<track>', methods=['GET', 'POST']) #,methods=['GET', 'POST'])
def payment(track):
    if 'username' not in session:
        return redirect('/login')

    if request.method == 'POST':
        # Εδώ θα κάνεις την "αγορά" (π.χ. απλά αναβάθμιση στη βάση)
        conn = get_db()
        cursor = conn.cursor()

        column_map = {
            'science': 'has_science',
            'health': 'has_health',
            'economics': 'has_economics',
            'humanities': 'has_humanities'
        }

        if track not in column_map:
            return "Invalid track", 404

        cursor.execute(f'''
            UPDATE users SET {column_map[track]} = 1 WHERE username = ?
        ''', (session['username'],))
        conn.commit()
        conn.close()

        return redirect(url_for('track_access', track_name=track))

    return render_template('payment.html', track=track)

@app.route('/create-checkout-session/<track>', methods=['POST'])
def create_checkout_session(track):
    if 'username' not in session:
        return redirect('/login')

    domain_url = 'https://panellele-app-4.onrender.com'  # Ανέβασε σε production αν χρειαστεί

    # Αντιστοίχιση track -> Stripe Price ID (από το Stripe dashboard σου)
    price_lookup = {
        'science': 'price_1RT8VwBZWTh3SvobwKAQBzII',
        'health': 'price_1RT8X6BZWTh3Svoblk67THSU',
        'economics': 'price_1RT8YMBZWTh3SvobnIyzGdJt',
        'humanities': 'price_1RT8YyBZWTh3Svobs1hER2aE'
    }

    if track not in price_lookup:
        return "Invalid track", 400

    try:
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price': price_lookup[track],
                'quantity': 1
            }],
            mode='subscription',
            success_url=domain_url + f'/payment/success/{track}',
            cancel_url=domain_url + '/home',
        )
        return jsonify({'id': checkout_session.id})
    except Exception as e:
        return jsonify(error=str(e)), 500

@app.route('/payment/success/<track>')
def payment_success(track):
    if 'username' not in session:
        return redirect('/login')

    column_map = {
        'science': 'has_science',
        'health': 'has_health',
        'economics': 'has_economics',
        'humanities': 'has_humanities'
    }

    expiry_map = {
        'science': 'science_expiry',
        'health': 'health_expiry',
        'economics': 'economics_expiry',
        'humanities': 'humanities_expiry'
    }

    if track not in column_map:
        return "Invalid track", 404

    expiry_date = (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d")

    # Ενημέρωση χρήστη στη βάση ότι απέκτησε πρόσβαση
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(f'''
        UPDATE users SET {column_map[track]} = 1, {expiry_map[track]} = ? WHERE username = ?
    ''', (expiry_date, session['username'],))
    conn.commit()
    conn.close()

    flash("Η πληρωμή ήταν επιτυχής! Καλώς ήρθες στο μάθημα.")
    return redirect(url_for('track_access', track_name=track))

@app.route('/lessons/physics')
def physics():
    return render_template('firstfield/fysiki.html')

@app.route('/lessons/math')
def math():
    return render_template('firstfield/maths.html')

@app.route('/lessons/xhmeia')
def xhmeia():
    return render_template('firstfield/xhmeia.html')

@app.route('/lessons/ekthesi')
def ekthesi():
    return render_template('firstfield/ekthesi.html')


# --- DB Setup ---
if __name__ == '__main__':
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            gender TEXT,
            age INTEGER,
            reset_token TEXT,
            token_expiration INTEGER
        )
    ''')
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(users)")
    existing_columns = [col['name'] for col in cursor.fetchall()]  # <-- Εδώ ορίζουμε existing_columns

    # Οι νέες στήλες που θέλεις να προσθέσεις
    new_columns = {
        'has_science': "INTEGER DEFAULT 0",
        'has_health': "INTEGER DEFAULT 0",
        'has_economics': "INTEGER DEFAULT 0",
        'has_humanities': "INTEGER DEFAULT 0",
        'science_expiry': "DATE",
        'health_expiry': "DATE",
        'economics_expiry': "DATE",
        'humanities_expiry': "DATE"
    }

    # Προσθήκη μόνο αν δεν υπάρχουν ήδη
    for column, definition in new_columns.items():
        if column not in existing_columns:
            cursor.execute(f"ALTER TABLE users ADD COLUMN {column} {definition}")

    conn.commit()
    conn.close()
    app.run(debug=True, host='0.0.0.0', port=5000)