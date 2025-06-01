import sqlite3

conn = sqlite3.connect('users.db')
cursor = conn.cursor()

# Προσθέτουμε στήλες αν δεν υπάρχουν
try:
    cursor.execute("ALTER TABLE users ADD COLUMN reset_token TEXT")
except sqlite3.OperationalError:
    print("reset_token already exists")

try:
    cursor.execute("ALTER TABLE users ADD COLUMN token_expiration INTEGER")
except sqlite3.OperationalError:
    print("token_expiration already exists")

conn.commit()
conn.close()

print("✅ Migration complete")
