from flask import Flask, render_template, request, redirect, session, flash, url_for
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to something secure

# Add this after app = Flask(...)
# from flask_wtf.csrf import CSRFProtect
# csrf = CSRFProtect(app)


DATABASE = 'db.sqlite'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# ---------- HOME ----------
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect('/dashboard')
    return redirect('/login')

# # ---------- REGISTER ----------
# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = generate_password_hash(request.form['password'])
#         role = request.form.get('role', 'member')

#         conn = get_db_connection()
#         try:
#             conn.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', (username, password, role))
#             conn.commit()
#             flash('User registered successfully. Please login.', 'success')
#             return redirect('/login')
#         except sqlite3.IntegrityError:
#             flash('Username already taken!', 'danger')
#         finally:
#             conn.close()

#     return render_template('register.html')

#--------------✅ 4. ADMIN ADD-USER FORM--------------#

@app.route('/admin_register', methods=['GET', 'POST'])
def admin_register():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    current_user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()

    if current_user['role'] != 'admin':
        conn.close()
        # return "Access denied", 403
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('dashboard'))


    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])

        try:
            conn.execute('INSERT INTO users (username, password, role) VALUES (?, ?, "member")', (username, password))
            conn.commit()
        except sqlite3.IntegrityError:
            return "Username already exists"
        finally:
            conn.close()
        return redirect(url_for('manage_users'))

    conn.close()
    return render_template('admin_register.html')


# ---------- LOGIN ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash('Logged in successfully.', 'success')
            return redirect('/dashboard')
        else:
            flash('Invalid credentials.', 'danger')

    return render_template('login.html')

# ---------- LOGOUT ----------
@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect('/login')

# ---------- DASHBOARD (Placeholder for now) ----------


# @app.route('/dashboard')
# def dashboard():
#     if 'user_id' not in session:
#         return redirect(url_for('login'))

#     conn = get_db_connection()
#     user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
#     # Get recent 5 expenses
#     expenses = conn.execute('''
#         SELECT e.description, e.amount, e.date, u.username AS paid_by
#         FROM expenses e
#         JOIN users u ON e.paid_by = u.id
#         ORDER BY e.date DESC
#         LIMIT 5
#     ''').fetchall()
    
#     conn.close()
#     return render_template('dashboard.html', user=user, expenses=expenses)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()

    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()

    # Get total expense
    total_expense = conn.execute('SELECT IFNULL(SUM(amount), 0) FROM expenses').fetchone()[0]

    # Get current month's expense
    monthly_expense = conn.execute('''
        SELECT IFNULL(SUM(amount), 0)
        FROM expenses
        WHERE strftime('%Y-%m', date) = strftime('%Y-%m', 'now')
    ''').fetchone()[0]

    # Get total number of users
    user_count = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]

    # Get recent 5 expenses
    expenses = conn.execute('''
        SELECT e.description, e.amount, e.date, u.username AS paid_by
        FROM expenses e
        JOIN users u ON e.paid_by = u.id
        ORDER BY e.date DESC
        LIMIT 5
    ''').fetchall()

    conn.close()

    return render_template(
        'dashboard.html',
        user=user,
        expenses=expenses,
        total_expense=round(total_expense, 2),
        monthly_expense=round(monthly_expense, 2),
        user_count=user_count
    )





@app.route('/add_expense', methods=['GET', 'POST'])
def add_expense():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    users = conn.execute('SELECT id, username FROM users').fetchall()

    if request.method == 'POST':
        description = request.form['description']
        amount = float(request.form['amount'])
        paid_by = int(request.form['paid_by'])
        selected_users = request.form.getlist('shared_with')

        # Insert into expenses
        conn.execute(
            'INSERT INTO expenses (description, amount, paid_by, date) VALUES (?, ?, ?, DATE("now"))',
            (description, amount, paid_by)
        )
        expense_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]

        # Calculate equal share
        share = round(amount / len(selected_users), 2)

        for user_id in selected_users:
            conn.execute(
                'INSERT INTO expense_shares (expense_id, user_id, share_amount) VALUES (?, ?, ?)',
                (expense_id, int(user_id), share)
            )

        conn.commit()
        conn.close()
        flash('Expense added successfully.', 'success')
        return redirect(url_for('dashboard'))

    conn.close()
    return render_template('add_expense.html', users=users)


@app.route('/manage_users')
def manage_users():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    current_user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()

    # Only admin can access
    if current_user['role'] != 'admin':
        conn.close()
        # return "Access denied", 403
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('dashboard'))


    users = conn.execute('SELECT * FROM users WHERE role != "admin"').fetchall()
    conn.close()
    return render_template('manage_users.html', users=users)


# @app.route('/manage_user', methods=['GET', 'POST'])
# def manage_user():
#     if 'user_id' not in session:
#         return redirect(url_for('login'))

#     conn = get_db_connection()

#     # Check if current user is admin
#     current_user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
#     if current_user['role'] != 'admin':
#         conn.close()
#         flash('Only admin can manage users.', 'danger')
#         return redirect(url_for('dashboard'))

#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']
#         role = request.form['role']

#         try:
#             conn.execute(
#                 'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
#                 (username, password, role)
#             )
#             conn.commit()
#             flash('User added successfully.', 'success')
#         except sqlite3.IntegrityError:
#             flash('Username already exists.', 'danger')

#     users = conn.execute('SELECT * FROM users').fetchall()
#     conn.close()
#     return render_template('manage_user.html', users=users)
# @app.route('/view_expense')
# def view_expense():
#     if 'user_id' not in session:
#         return redirect(url_for('login'))

#     conn = get_db_connection()

#     # Fetch current user info (for greeting)
#     user_id = session['user_id']
#     user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

#     # 🚨 Show all expenses to everyone (no role check)
#     expenses = conn.execute('''
#         SELECT expenses.*, users.username AS paid_by_name
#         FROM expenses
#         JOIN users ON expenses.paid_by = users.id
#         ORDER BY date DESC
#     ''').fetchall()

#     conn.close()
#     return render_template('view_expense.html', expenses=expenses, username=user['username'])
@app.route('/view_expenses')
def view_expenses():
    user_id = session.get('user_id')
    conn = get_db_connection()
    expenses_raw = conn.execute('''
        SELECT e.*, u.username AS paid_by_name
        FROM expenses e
        JOIN users u ON e.paid_by = u.id
    ''').fetchall()

    expenses = []
    for exp in expenses_raw:
        expense = dict(exp)

        shares = conn.execute('''
            SELECT es.id, es.user_id, es.share_amount, es.payment_status, u.username
            FROM expense_shares es
            JOIN users u ON es.user_id = u.id
            WHERE es.expense_id = ?
        ''', (expense['id'],)).fetchall()

        expense['shares'] = [dict(share) for share in shares]
        expenses.append(expense)

    conn.close()
    return render_template('view_expenses.html', expenses=expenses, session_user_id=user_id)


# @app.route('/mark_paid/<int:share_id>', methods=['POST'])
# def mark_paid(share_id):
#     user_id = session.get('user_id')
#     conn = get_db_connection()
#     conn.execute('''
#         UPDATE expense_shares
#         SET payment_status = 'paid'
#         WHERE id = ? AND user_id = ?
#     ''', (share_id, user_id))
#     conn.commit()
#     conn.close()
#     return redirect(url_for('view_expenses'))

@app.route('/mark_paid/<int:share_id>', methods=['POST'])
def mark_paid(share_id):
    conn = get_db_connection()
    share = conn.execute('SELECT * FROM expense_shares WHERE id = ?', (share_id,)).fetchone()

    # Get the related expense to check who paid it
    expense = conn.execute('SELECT * FROM expenses WHERE id = ?', (share['expense_id'],)).fetchone()

    # Ensure only the payer can mark someone as paid
    if expense['paid_by'] != session['user_id']:
        conn.close()
        # return "Unauthorized", 403
        flash('Access denied: Unauthorized.', 'danger')
        return redirect(url_for('dashboard'))


    # Mark as paid
    conn.execute('UPDATE expense_shares SET payment_status = ? WHERE id = ?', ('paid', share_id))
    conn.commit()
    conn.close()
    return redirect(request.referrer or url_for('index'))


@app.route('/edit/<int:expense_id>', methods=['GET', 'POST'])
def edit_expense(expense_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()

    expense = cursor.execute('SELECT * FROM expenses WHERE id = ?', (expense_id,)).fetchone()
    if not expense:
        flash("Expense not found.", "error")
        conn.close()
        return redirect(url_for('view_expenses'))

    users = cursor.execute('SELECT id, username FROM users').fetchall()

    if request.method == 'POST':
        description = request.form['description']
        amount = float(request.form['amount'])
        paid_by = int(request.form['paid_by'])
        shared_with_form = request.form.getlist('shared_with')
        # date = request.form.get('date', expense['date'])

        cursor.execute('''
            UPDATE expenses 
            SET description = ?, amount = ?, paid_by = ?
            WHERE id = ?
        ''', (description, amount, paid_by,  expense_id))

        cursor.execute('DELETE FROM expense_shares WHERE expense_id = ?', (expense_id,))

        num_users = len(shared_with_form)
        share_amount = round(amount / num_users, 2) if num_users > 0 else 0.0

        for user_id in shared_with_form:
            cursor.execute('''
                INSERT INTO expense_shares (expense_id, user_id, share_amount, payment_status)
                VALUES (?, ?, ?, ?)
            ''', (expense_id, int(user_id), share_amount, 'unpaid'))

        conn.commit()
        conn.close()
        flash('Expense updated successfully.', 'success')
        return redirect(url_for('view_expenses'))

    conn.close()
    return render_template('edit_expense.html', expense=expense, users=users)

@app.route('/delete_expense/<int:expense_id>', methods=['POST'])
def delete_expense(expense_id):
    conn = get_db_connection()
    
    # Delete from expense_shares table first due to foreign key constraint
    conn.execute('DELETE FROM expense_shares WHERE expense_id = ?', (expense_id,))
    
    # Then delete from expenses
    conn.execute('DELETE FROM expenses WHERE id = ?', (expense_id,))
    
    conn.commit()
    conn.close()
    
    flash("Expense deleted successfully!", "success")
    return redirect(url_for('view_expenses'))


@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    current_user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()

    if current_user['role'] != 'admin':
        conn.close()
        # return "Access denied", 403
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('dashboard'))


    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('manage_users'))






if __name__ == '__main__':
    if not os.path.exists(DATABASE):
        with open('schema.sql', 'r') as f:
            schema = f.read()
        conn = get_db_connection()
        conn.executescript(schema)
        conn.close()
    app.run(debug=True)
