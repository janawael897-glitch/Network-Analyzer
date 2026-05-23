import sqlite3
c = sqlite3.connect('packetguard.db')
updated = c.execute("UPDATE users SET role='analyst' WHERE role='user'").rowcount
c.commit()
c.close()
print(f"Done — {updated} user(s) updated to analyst.")
