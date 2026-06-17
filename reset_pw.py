import sqlite3, hashlib, secrets
db = sqlite3.connect('packetguard.db')
salt = secrets.token_hex(16)
dk = hashlib.pbkdf2_hmac('sha256', b'admin123', salt.encode(), 260000)
sep = '$'
new_hash = 'pbkdf2' + sep + 'sha256' + sep + salt + sep + dk.hex()
db.execute('UPDATE users SET password=? WHERE email=?', (new_hash, 'admin@packetguard.io'))
db.commit()
db.close()
print('Done - password reset to admin123')
