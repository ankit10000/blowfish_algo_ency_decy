from flask import Flask, request, render_template, send_from_directory, abort
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import json
import os
import hashlib

app = Flask(__name__)

# Directory to store uploaded and processed files
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Supported Cipher Modes
MODES = {
    "ECB": Blowfish.MODE_ECB,
    "CBC": Blowfish.MODE_CBC,
    "CFB": Blowfish.MODE_CFB,
    "OFB": Blowfish.MODE_OFB,
}

# Function to compute MD5 checksum
def compute_md5(file_path):
    hasher = hashlib.md5()
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            hasher.update(chunk)
    return hasher.hexdigest()

# Encryption Function
def encrypt_blowfish(data, key, mode):
    key_bytes = key.encode('utf-8')
    cipher_mode = MODES.get(mode, Blowfish.MODE_ECB)

    if cipher_mode in [Blowfish.MODE_CBC, Blowfish.MODE_CFB, Blowfish.MODE_OFB]:
        iv = get_random_bytes(Blowfish.block_size)
        cipher = Blowfish.new(key_bytes, cipher_mode, iv)
        encrypted_bytes = iv + cipher.encrypt(pad(data.encode('utf-8'), Blowfish.block_size))
    elif cipher_mode == Blowfish.MODE_CTR:
        nonce = get_random_bytes(8)
        cipher = Blowfish.new(key_bytes, cipher_mode, nonce=nonce)
        encrypted_bytes = nonce + cipher.encrypt(data.encode('utf-8'))
    else:
        cipher = Blowfish.new(key_bytes, cipher_mode)
        encrypted_bytes = cipher.encrypt(pad(data.encode('utf-8'), Blowfish.block_size))

    return base64.b64encode(encrypted_bytes).decode('utf-8')

# Decryption Function
def decrypt_blowfish(encrypted_data, key, mode):
    key_bytes = key.encode('utf-8')
    cipher_mode = MODES.get(mode, Blowfish.MODE_ECB)
    encrypted_bytes = base64.b64decode(encrypted_data)

    if cipher_mode in [Blowfish.MODE_CBC, Blowfish.MODE_CFB, Blowfish.MODE_OFB]:
        iv = encrypted_bytes[:Blowfish.block_size]
        cipher = Blowfish.new(key_bytes, cipher_mode, iv)
        decrypted_bytes = unpad(cipher.decrypt(encrypted_bytes[Blowfish.block_size:]), Blowfish.block_size)
    elif cipher_mode == Blowfish.MODE_CTR:
        nonce = encrypted_bytes[:8]
        cipher = Blowfish.new(key_bytes, cipher_mode, nonce=nonce)
        decrypted_bytes = cipher.decrypt(encrypted_bytes[8:])
    else:
        cipher = Blowfish.new(key_bytes, cipher_mode)
        decrypted_bytes = unpad(cipher.decrypt(encrypted_bytes), Blowfish.block_size)

    return decrypted_bytes.decode('utf-8')

@app.route('/', methods=['GET', 'POST'])
def index():
    processed_files = []
    
    if request.method == 'POST':
        key = request.form.get('key')
        operation = request.form.get('operation')
        cipher_mode = request.form.get('mode')
        uploaded_files = request.files.getlist('files')

        if not key or not uploaded_files:
            return "❌ Please provide an encryption key and select files."

        for uploaded_file in uploaded_files:
            original_name = uploaded_file.filename.rsplit(".", 1)[0]
            input_path = os.path.join(UPLOAD_FOLDER, f"{original_name}.json")
            output_path = os.path.join(UPLOAD_FOLDER, f"{operation}_{original_name}.json")

            uploaded_file.save(input_path)

            try:
                with open(input_path, 'r', encoding='utf-8') as infile:
                    data = json.load(infile)

                if operation == 'encrypt':
                    processed_data = encrypt_blowfish(json.dumps(data), key, cipher_mode)
                else:
                    processed_data = json.loads(decrypt_blowfish(data, key, cipher_mode))

                with open(output_path, 'w', encoding='utf-8') as outfile:
                    json.dump(processed_data, outfile, ensure_ascii=False, indent=4)

                md5_hash = compute_md5(output_path)
                processed_files.append((os.path.basename(output_path), md5_hash))

            except Exception as e:
                return f"❌ Error processing {uploaded_file.filename}: {e}"

    return render_template('index.html', processed_files=processed_files)



@app.route('/download/<filename>')
def download_file(filename):
    try:
        return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)
    except FileNotFoundError:
        abort(404, description="File not found!")

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
