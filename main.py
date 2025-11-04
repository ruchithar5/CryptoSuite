from flask import Flask, render_template, request, redirect, url_for, flash
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# ----------------- Caesar -----------------
def caesar_encrypt(text, k):
    k = k % 26
    out = []
    for ch in text:
        if 'A' <= ch <= 'Z':
            out.append(chr((ord(ch)-65 + k) % 26 + 65))
        elif 'a' <= ch <= 'z':
            out.append(chr((ord(ch)-97 + k) % 26 + 97))
        else:
            out.append(ch)
    return ''.join(out)

def caesar_decrypt(ct, k):
    return caesar_encrypt(ct, -k)

# ----------------- Playfair -----------------
def generate_playfair_matrix(keyword):
    kw = ""
    seen = set()
    for ch in keyword.upper():
        if not ch.isalpha(): continue
        c = 'I' if ch == 'J' else ch
        if c not in seen:
            kw += c
            seen.add(c)
    for i in range(65, 91):
        c = chr(i)
        if c == 'J': continue
        if c not in seen:
            kw += c
            seen.add(c)
    matrix = [list(kw[i*5:(i+1)*5]) for i in range(5)]
    return matrix

def find_in_matrix(matrix, ch):
    ch = 'I' if ch == 'J' else ch
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == ch:
                return r, c
    raise ValueError("Char not found: "+ch)

def prepare_playfair_plaintext(pt):
    s = [ ('I' if ch.upper()=='J' else ch.upper()) for ch in pt if ch.isalpha() ]
    i = 0
    pairs = []
    while i < len(s):
        a = s[i]
        b = s[i+1] if i+1 < len(s) else None
        if b is None:
            pairs.append((a,'X'))
            i += 1
        elif a == b:
            pairs.append((a,'X'))
            i += 1
        else:
            pairs.append((a,b))
            i += 2
    return pairs

def playfair_encrypt(pt, keyword):
    matrix = generate_playfair_matrix(keyword)
    pairs = prepare_playfair_plaintext(pt)
    ct = []
    for a,b in pairs:
        ra,ca = find_in_matrix(matrix,a)
        rb,cb = find_in_matrix(matrix,b)
        if ra == rb:
            ct.append(matrix[ra][(ca+1)%5])
            ct.append(matrix[rb][(cb+1)%5])
        elif ca == cb:
            ct.append(matrix[(ra+1)%5][ca])
            ct.append(matrix[(rb+1)%5][cb])
        else:
            ct.append(matrix[ra][cb])
            ct.append(matrix[rb][ca])
    return ''.join(ct), matrix, pairs

def playfair_decrypt(ct, keyword):
    matrix = generate_playfair_matrix(keyword)
    s = [ch for ch in ct.upper() if ch.isalpha()]
    pairs = [(s[i], s[i+1]) for i in range(0,len(s),2)]
    pt = []
    for a,b in pairs:
        ra,ca = find_in_matrix(matrix,a)
        rb,cb = find_in_matrix(matrix,b)
        if ra == rb:
            pt.append(matrix[ra][(ca-1)%5])
            pt.append(matrix[rb][(cb-1)%5])
        elif ca == cb:
            pt.append(matrix[(ra-1)%5][ca])
            pt.append(matrix[(rb-1)%5][cb])
        else:
            pt.append(matrix[ra][cb])
            pt.append(matrix[rb][ca])
    return ''.join(pt), matrix, pairs

# ----------------- Hill (2x2) -----------------
def egcd(a,b):
    if a == 0:
        return (b,0,1)
    g,y,x = egcd(b%a, a)
    return (g, x - (b//a)*y, y)

def modinv(a, m):
    g,x,y = egcd(a % m, m)
    if g != 1:
        return None
    return x % m

def hill_encrypt_2x2(pt, K):
    s = [ch for ch in pt.upper() if ch.isalpha()]
    if len(s) % 2 == 1:
        s.append('X')
    nums = [ord(ch)-65 for ch in s]
    ct_chars = []
    for i in range(0, len(nums), 2):
        v0, v1 = nums[i], nums[i+1]
        c0 = (K[0][0]*v0 + K[0][1]*v1) % 26
        c1 = (K[1][0]*v0 + K[1][1]*v1) % 26
        ct_chars.append(chr(c0+65))
        ct_chars.append(chr(c1+65))
    return ''.join(ct_chars)

def hill_decrypt_2x2(ct, K):
    a,b = K[0][0], K[0][1]
    c,d = K[1][0], K[1][1]
    det = (a*d - b*c) % 26
    inv_det = modinv(det, 26)
    if inv_det is None:
        return None, None, det
    invK = [
        [(inv_det * d) % 26, (inv_det * (-b)) % 26],
        [(inv_det * (-c)) % 26, (inv_det * a) % 26]
    ]
    s = [ch for ch in ct.upper() if ch.isalpha()]
    nums = [ord(ch)-65 for ch in s]
    pt_chars = []
    for i in range(0, len(nums), 2):
        v0, v1 = nums[i], nums[i+1]
        p0 = (invK[0][0]*v0 + invK[0][1]*v1) % 26
        p1 = (invK[1][0]*v0 + invK[1][1]*v1) % 26
        pt_chars.append(chr(p0+65))
        pt_chars.append(chr(p1+65))
    return ''.join(pt_chars), invK, det

# ----------------- One-Time Pad -----------------
def generate_otp_key(length):
    rb = os.urandom(length)
    return [b % 26 for b in rb]

def otp_encrypt(plaintext, key_nums):
    s = [ch for ch in plaintext.upper() if ch.isalpha()]
    if len(s) != len(key_nums):
        raise ValueError("Key length must equal plaintext letters count for OTP")
    ct = []
    for i,ch in enumerate(s):
        p = ord(ch)-65
        c = (p + key_nums[i]) % 26
        ct.append(chr(c+65))
    return ''.join(ct)

def otp_decrypt(ciphertext, key_nums):
    s = [ch for ch in ciphertext.upper() if ch.isalpha()]
    if len(s) != len(key_nums):
        raise ValueError("Key length must equal ciphertext letters count for OTP")
    pt = []
    for i,ch in enumerate(s):
        c = ord(ch)-65
        p = (c - key_nums[i]) % 26
        pt.append(chr(p+65))
    return ''.join(pt)

# ----------------- Flask routes -----------------
@app.route('/')
def index():
    return render_template('index.html')

# Caesar
@app.route('/caesar', methods=['GET','POST'])
def caesar():
    result = None
    decrypted = None
    if request.method == 'POST':
        action = request.form.get('action')
        text = request.form.get('text','')
        try:
            key = int(request.form.get('key','0'))
        except:
            flash("Key must be an integer.", "danger")
            return redirect(url_for('caesar'))
        if action == 'Encrypt':
            result = caesar_encrypt(text, key)
        else:
            result = caesar_decrypt(text, key)
    return render_template('caesar.html', result=result)

# Playfair
@app.route('/playfair', methods=['GET','POST'])
def playfair():
    result = None
    matrix = None
    pairs = None
    if request.method == 'POST':
        action = request.form.get('action')
        text = request.form.get('text','')
        keyword = request.form.get('keyword','KEY')
        if not keyword.strip():
            flash("Keyword required.", "danger")
            return redirect(url_for('playfair'))
        if action == 'Encrypt':
            result, matrix, pairs = playfair_encrypt(text, keyword)
        else:
            result, matrix, pairs = playfair_decrypt(text, keyword)
    return render_template('playfair.html', result=result, matrix=matrix, pairs=pairs)

# Hill 2x2
@app.route('/hill', methods=['GET','POST'])
def hill():
    result = None
    invK = None
    det = None
    if request.method == 'POST':
        action = request.form.get('action')
        text = request.form.get('text','')
        try:
            a = int(request.form.get('a')) % 26
            b = int(request.form.get('b')) % 26
            c = int(request.form.get('c')) % 26
            d = int(request.form.get('d')) % 26
            K = [[a,b],[c,d]]
        except:
            flash("Matrix entries must be integers.", "danger")
            return redirect(url_for('hill'))
        if action == 'Encrypt':
            result = hill_encrypt_2x2(text, K)
        else:
            res = hill_decrypt_2x2(text, K)
            if res[0] is None:
                flash(f"Key matrix not invertible mod 26. Determinant = {res[2]}", "danger")
            else:
                result, invK, det = res
    return render_template('hill.html', result=result, invK=invK, det=det)

# OTP
@app.route('/otp', methods=['GET','POST'])
def otp():
    result = None
    key_nums = None
    decrypted = None
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'Generate & Encrypt':
            pt = request.form.get('text','')
            letters = [ch for ch in pt.upper() if ch.isalpha()]
            if not letters:
                flash("Plaintext must contain letters for OTP encryption.", "danger")
                return redirect(url_for('otp'))
            key_nums = generate_otp_key(len(letters))
            ct = otp_encrypt(pt, key_nums)
            result = ct
            # store key in form (render) as numbers; user should save it for decryption
            return render_template('otp.html', result=result, key_nums=key_nums)
        elif action == 'Decrypt':
            ct = request.form.get('text','')
            key_text = request.form.get('keynums','').strip()
            if not key_text:
                flash("Please paste key numbers as comma-separated values.", "danger")
                return redirect(url_for('otp'))
            try:
                key_nums = [int(x.strip()) % 26 for x in key_text.split(',') if x.strip()!='']
            except:
                flash("Invalid key numbers format.", "danger")
                return redirect(url_for('otp'))
            try:
                decrypted = otp_decrypt(ct, key_nums)
                result = decrypted
            except Exception as e:
                flash(str(e), "danger")
    return render_template('otp.html', result=result, key_nums=key_nums)

if __name__ == '__main__':
    app.run(debug=True)

