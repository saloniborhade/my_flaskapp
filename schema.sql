DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS expenses;
DROP TABLE IF EXISTS expense_shares;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin', 'member'))
);

CREATE TABLE expenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    description TEXT NOT NULL,
    amount REAL NOT NULL,
    paid_by INTEGER,
    date TEXT,
    FOREIGN KEY (paid_by) REFERENCES users(id)
);

CREATE TABLE expense_shares (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    expense_id INTEGER,
    user_id INTEGER,
    share_amount REAL,
    FOREIGN KEY (expense_id) REFERENCES expenses(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);
