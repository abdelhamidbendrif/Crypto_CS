from flask import Flask, request, jsonify, render_template
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import base64
import os

app = Flask(__name__)

SECRET_KEY = b'MySuperSecretKey'  # 16 bytes for AES-128

def encrypt_text(plaintext: str) -> str:
    iv = os.urandom(16)
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    return base64.b64encode(iv + ct_bytes).decode('utf-8')

def decrypt_text(ciphertext: str) -> str:
    raw = base64.b64decode(ciphertext)
    iv = raw[:16]
    ct = raw[16:]
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

def sha256_hash(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

# Web UI 

@app.route('/')
def index():
    return render_template('index.html')

# REST API 

@app.route('/crypt', methods=['POST'])
def crypt():
    data = request.get_json()
    text = data.get('text', '')
    if not text:
        return jsonify({'error': 'No text provided'}), 400
    encrypted = encrypt_text(text)
    return jsonify({'encrypted': encrypted})

@app.route('/decrypt', methods=['GET'])
def decrypt():
    ciphertext = request.args.get('text', '')
    if not ciphertext:
        return jsonify({'error': 'No text provided'}), 400
    try:
        decrypted = decrypt_text(ciphertext)
        return jsonify({'decrypted': decrypted})
    except Exception as e:
        return jsonify({'error': 'Decryption failed. Invalid ciphertext.'}), 400

@app.route('/hash', methods=['POST'])
def hash_text():
    data = request.get_json()
    text = data.get('text', '')
    compare = data.get('compare', None)
    if not text:
        return jsonify({'error': 'No text provided'}), 400
    h = sha256_hash(text)
    result = {'hash': h}
    if compare is not None:
        result['match'] = (h == compare)
        result['modified'] = (h != compare)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
