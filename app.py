from flask import Flask, render_template, request, redirect, url_for, session, flash
import mysql.connector
from mysql.connector import Error
from werkzeug.security import generate_password_hash, check_password_hash
import re
from datetime import date

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# MySQL config (edit these for your WAMP setup)
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'habitdb',
    'charset': 'utf8mb4'
}

def get_db_connection():
    return mysql.connector.connect(**db_config)

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            email VARCHAR(100) UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            xp INT DEFAULT 0,
            level INT DEFAULT 1,
            current_streak INT DEFAULT 0,
            longest_streak INT DEFAULT 0,
            last_completion_date DATE
        )
    ''')
    
    # Create challenges table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS challenges (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            name VARCHAR(100) NOT NULL,
            frequency VARCHAR(20) NOT NULL,
            prerequisite_challenge_id INT,
            prerequisite_stars INT,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (prerequisite_challenge_id) REFERENCES challenges(id)
        )
    ''')
    
    # Create milestones table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS milestones (
            id INT AUTO_INCREMENT PRIMARY KEY,
            challenge_id INT NOT NULL,
            description VARCHAR(255) NOT NULL,
            duration_days INT NOT NULL,
            stars INT NOT NULL,
            milestone_order INT NOT NULL,
            FOREIGN KEY (challenge_id) REFERENCES challenges(id)
        )
    ''')
    
    # Create completions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS completions (
            id INT AUTO_INCREMENT PRIMARY KEY,
            challenge_id INT NOT NULL,
            user_id INT NOT NULL,
            completion_date DATE NOT NULL,
            FOREIGN KEY (challenge_id) REFERENCES challenges(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Create achievements table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS achievements (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            description TEXT NOT NULL,
            xp_reward INT NOT NULL,
            icon VARCHAR(50) NOT NULL
        )
    ''')
    
    # Create user_achievements table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_achievements (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            achievement_id INT NOT NULL,
            earned_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (achievement_id) REFERENCES achievements(id)
        )
    ''')
    
    conn.commit()
    cursor.close()
    conn.close()

# Initialize database on startup
init_db()

@app.route('/')
def home():
    if 'loggedin' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        if user and check_password_hash(user['password_hash'], password):
            session['loggedin'] = True
            session['id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('dashboard'))
        else:
            flash('Incorrect username or password!', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm = request.form['confirm']
        if password != confirm:
            flash('Passwords do not match!', 'danger')
            return render_template('register.html')
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        account = cursor.fetchone()
        if account:
            flash('Username already exists!', 'danger')
        elif not re.match(r'^[A-Za-z0-9_]{3,}$', username):
            flash('Username must be at least 3 characters and contain only letters, numbers, and underscores.', 'danger')
        else:
            hash_pw = generate_password_hash(password)
            cursor.execute('INSERT INTO users (username, password_hash) VALUES (%s, %s)', (username, hash_pw))
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            cursor.close()
            conn.close()
            return redirect(url_for('login'))
        cursor.close()
        conn.close()
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/add_challenge', methods=['POST'])
def add_challenge():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    user_id = session['id']
    name = request.form.get('challenge_name')
    frequency = request.form.get('frequency')
    prerequisite_challenge_id = request.form.get('prerequisite_challenge_id')
    prerequisite_stars = request.form.get('prerequisite_stars')
    if prerequisite_challenge_id == '' or prerequisite_challenge_id is None:
        prerequisite_challenge_id = None
        prerequisite_stars = None
    milestones = []
    for i in range(1, 4):
        desc = request.form.get(f'milestone_desc{i}')
        days = request.form.get(f'milestone_days{i}')
        stars = request.form.get(f'milestone_stars{i}')
        if desc and days and stars:
            milestones.append((desc, int(days), int(stars), i))
    if not name or not milestones:
        flash('Please provide a challenge name and at least one milestone.', 'danger')
        return redirect(url_for('dashboard'))
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO challenges (user_id, name, frequency, prerequisite_challenge_id, prerequisite_stars) VALUES (%s, %s, %s, %s, %s)', (user_id, name, frequency, prerequisite_challenge_id, prerequisite_stars))
    challenge_id = cursor.lastrowid
    for desc, days, stars, order in milestones:
        cursor.execute('INSERT INTO milestones (challenge_id, description, duration_days, stars, milestone_order) VALUES (%s, %s, %s, %s, %s)', (challenge_id, desc, days, stars, order))
    conn.commit()
    cursor.close()
    conn.close()
    flash('Challenge saved!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/complete_challenge/<int:challenge_id>', methods=['POST'])
def complete_challenge(challenge_id):
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    user_id = session['id']
    today = date.today()
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get user's current streak and last completion date
    cursor.execute('SELECT current_streak, last_completion_date FROM users WHERE id = %s', (user_id,))
    user_data = cursor.fetchone()
    current_streak = user_data[0]
    last_completion_date = user_data[1]
    
    # Calculate new streak
    new_streak = 1
    if last_completion_date:
        days_since_last = (today - last_completion_date).days
        if days_since_last == 1:
            new_streak = current_streak + 1
        elif days_since_last > 1:
            new_streak = 1
    
    # Only insert if not already completed today
    cursor.execute('SELECT id FROM completions WHERE challenge_id = %s AND user_id = %s AND completion_date = %s', (challenge_id, user_id, today))
    if not cursor.fetchone():
        cursor.execute('INSERT INTO completions (challenge_id, user_id, completion_date) VALUES (%s, %s, %s)', (challenge_id, user_id, today))
        
        # Calculate XP gain
        base_xp = 50  # Daily completion bonus
        streak_bonus = new_streak * 25  # Streak bonus
        
        # Get challenge stars
        cursor.execute('''
            SELECT SUM(m.stars) 
            FROM milestones m 
            JOIN challenges c ON m.challenge_id = c.id 
            WHERE c.id = %s
        ''', (challenge_id,))
        stars = cursor.fetchone()[0] or 0
        stars_xp = stars * 100  # XP from stars
        
        total_xp = base_xp + streak_bonus + stars_xp
        
        # Update user's XP and streak
        cursor.execute('''
            UPDATE users 
            SET xp = xp + %s,
                current_streak = %s,
                last_completion_date = %s,
                longest_streak = CASE 
                    WHEN %s > longest_streak THEN %s 
                    ELSE longest_streak 
                END
            WHERE id = %s
        ''', (total_xp, new_streak, today, new_streak, new_streak, user_id))
        
        # Check for level up
        cursor.execute('SELECT xp, level FROM users WHERE id = %s', (user_id,))
        user_xp, current_level = cursor.fetchone()
        new_level = (user_xp // 1000) + 1
        
        if new_level > current_level:
            cursor.execute('UPDATE users SET level = %s WHERE id = %s', (new_level, user_id))
            flash(f'Level Up! You are now level {new_level}! 🎉', 'success')
        
        conn.commit()
        flash('Marked as done for today!', 'success')
    else:
        flash('Already marked as done for today.', 'danger')
    
    cursor.close()
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/delete_challenge/<int:challenge_id>', methods=['POST'])
def delete_challenge(challenge_id):
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    user_id = session['id']
    conn = get_db_connection()
    cursor = conn.cursor()
    # Only allow deleting user's own challenge
    cursor.execute('DELETE FROM challenges WHERE id = %s AND user_id = %s', (challenge_id, user_id))
    conn.commit()
    cursor.close()
    conn.close()
    flash('Challenge deleted!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    user_id = session['id']
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Get user stats
    cursor.execute('SELECT xp, level, current_streak, longest_streak FROM users WHERE id = %s', (user_id,))
    user_stats = cursor.fetchone()
    
    cursor.execute('SELECT * FROM challenges WHERE user_id = %s', (user_id,))
    challenges = cursor.fetchall()
    # For the prerequisite dropdown
    all_challenges = [dict(id=c['id'], name=c['name']) for c in challenges]
    total_stars_achieved = 0
    total_stars_possible = 0
    # Build a map of challenge_id to current stars for prerequisite checking
    challenge_stars = {}
    for challenge in challenges:
        cursor.execute('SELECT * FROM milestones WHERE challenge_id = %s ORDER BY milestone_order', (challenge['id'],))
        milestones = cursor.fetchall()
        cursor.execute('SELECT COUNT(*) as cnt FROM completions WHERE challenge_id = %s AND user_id = %s', (challenge['id'], user_id))
        completions_count = cursor.fetchone()['cnt']
        total_stars = sum(m['stars'] for m in milestones)
        current_stars = 0
        days_done = completions_count
        milestone_days_cumulative = 0
        next_milestone = None
        for m in milestones:
            milestone_days_cumulative += m['duration_days']
            if days_done >= milestone_days_cumulative:
                current_stars += m['stars']
            elif not next_milestone:
                days_left = milestone_days_cumulative - days_done
                next_milestone = f"{days_left} day(s) until next star"
        challenge['progress'] = f"{current_stars}/{total_stars}"
        challenge['next_milestone'] = next_milestone if next_milestone else 'All milestones complete!'
        total_stars_achieved += current_stars
        total_stars_possible += total_stars
        challenge_stars[challenge['id']] = current_stars
    # Now, check for locked status
    for challenge in challenges:
        locked = False
        lock_message = ''
        prerequisite_name = ''
        if challenge.get('prerequisite_challenge_id'):
            prereq_id = challenge['prerequisite_challenge_id']
            prereq_stars = challenge['prerequisite_stars'] or 0
            # Find the name of the prerequisite challenge
            prereq_name = next((c['name'] for c in challenges if c['id'] == prereq_id), 'Another Challenge')
            prerequisite_name = prereq_name
            # Check if enough stars in prerequisite
            if challenge_stars.get(prereq_id, 0) < prereq_stars:
                locked = True
                lock_message = f"Locked: Achieve {prereq_stars} star(s) in '{prereq_name}' to unlock."
        challenge['locked'] = locked
        challenge['lock_message'] = lock_message
        challenge['prerequisite_name'] = prerequisite_name
    cursor.close()
    conn.close()
    return render_template('dashboard.html', 
                         username=session['username'],
                         challenges=challenges,
                         total_stars_achieved=total_stars_achieved,
                         total_stars_possible=total_stars_possible,
                         all_challenges=all_challenges,
                         user_level=user_stats['level'],
                         user_xp=user_stats['xp'],
                         current_streak=user_stats['current_streak'],
                         longest_streak=user_stats['longest_streak'])

@app.route('/challenge/<int:challenge_id>')
def challenge_detail(challenge_id):
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    user_id = session['id']
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    # Get the challenge
    cursor.execute('SELECT * FROM challenges WHERE id = %s AND user_id = %s', (challenge_id, user_id))
    challenge = cursor.fetchone()
    if not challenge:
        cursor.close()
        conn.close()
        flash('Challenge not found.', 'danger')
        return redirect(url_for('dashboard'))
    # Get milestones
    cursor.execute('SELECT * FROM milestones WHERE challenge_id = %s ORDER BY milestone_order', (challenge_id,))
    milestones = cursor.fetchall()
    # Get completions
    cursor.execute('SELECT COUNT(*) as cnt FROM completions WHERE challenge_id = %s AND user_id = %s', (challenge_id, user_id))
    completions_count = cursor.fetchone()['cnt']
    # Calculate progress and next milestone
    total_stars = sum(m['stars'] for m in milestones)
    current_stars = 0
    days_done = completions_count
    milestone_days_cumulative = 0
    next_milestone = None
    for m in milestones:
        milestone_days_cumulative += m['duration_days']
        if days_done >= milestone_days_cumulative:
            current_stars += m['stars']
        elif not next_milestone:
            days_left = milestone_days_cumulative - days_done
            next_milestone = f"Next Milestone in {days_left} Days 🔥"
    progress = f"{current_stars}/{total_stars}"
    if not next_milestone:
        next_milestone = 'All milestones complete!'
    cursor.close()
    conn.close()
    return render_template('challenge_detail.html', challenge=challenge, milestones=milestones, next_milestone=next_milestone, progress=progress)

@app.route('/settings')
def settings():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    return render_template('settings.html')

@app.route('/change_password', methods=['POST'])
def change_password():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    user_id = session['id']
    old_password = request.form['old_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']
    if new_password != confirm_password:
        flash('New passwords do not match!', 'danger')
        return redirect(url_for('settings'))
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT password_hash FROM users WHERE id = %s', (user_id,))
    user = cursor.fetchone()
    if not user or not check_password_hash(user['password_hash'], old_password):
        flash('Old password is incorrect!', 'danger')
        cursor.close()
        conn.close()
        return redirect(url_for('settings'))
    new_hash = generate_password_hash(new_password)
    cursor.execute('UPDATE users SET password_hash = %s WHERE id = %s', (new_hash, user_id))
    conn.commit()
    cursor.close()
    conn.close()
    flash('Password changed successfully!', 'success')
    return redirect(url_for('settings'))

@app.route('/reset_account', methods=['POST'])
def reset_account():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    user_id = session['id']
    conn = get_db_connection()
    cursor = conn.cursor()
    # Delete completions, challenges, milestones for this user
    cursor.execute('SELECT id FROM challenges WHERE user_id = %s', (user_id,))
    challenge_ids = [row[0] for row in cursor.fetchall()]
    if challenge_ids:
        format_strings = ','.join(['%s'] * len(challenge_ids))
        cursor.execute(f'DELETE FROM milestones WHERE challenge_id IN ({format_strings})', tuple(challenge_ids))
        cursor.execute(f'DELETE FROM completions WHERE challenge_id IN ({format_strings})', tuple(challenge_ids))
        cursor.execute(f'DELETE FROM challenges WHERE id IN ({format_strings})', tuple(challenge_ids))
    # Reset XP, streaks
    cursor.execute('UPDATE users SET xp = 0, level = 1, current_streak = 0, longest_streak = 0, last_completion_date = NULL WHERE id = %s', (user_id,))
    conn.commit()
    cursor.close()
    conn.close()
    flash('Account reset successfully! All your challenges and progress have been deleted.', 'success')
    return redirect(url_for('settings'))

@app.route('/leaderboard')
def leaderboard():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    user_id = session['id']
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT id, username, level, xp, current_streak FROM users ORDER BY xp DESC, level DESC LIMIT 10')
    leaderboard = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('leaderboard.html', leaderboard=leaderboard, current_user_id=user_id)

if __name__ == '__main__':
    app.run(debug=True) 