from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from flask import Flask, request, jsonify, render_template
import base64

app = Flask(__name__)

# Load RSA keys
with open("private_key.pem", "rb") as priv_file:
    private_key = RSA.import_key(priv_file.read())

with open("public_key.pem", "rb") as pub_file:
    public_key = RSA.import_key(pub_file.read())

# Encryption Function
@app.route('/encrypt', methods=['POST'])
def encrypt_image():
    # Read the image file
    image_file = request.files['file']
    image_data = image_file.read()

    # Step 1: Encrypt image using AES
    aes_key = get_random_bytes(16)  # AES key (16 bytes for AES-128)
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(image_data)

    # Step 2: Encrypt the AES key using RSA
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    # Prepare the encrypted data to send back
    encrypted_data = {
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
        'nonce': base64.b64encode(cipher_aes.nonce).decode('utf-8'),
        'tag': base64.b64encode(tag).decode('utf-8'),
        'encrypted_aes_key': base64.b64encode(encrypted_aes_key).decode('utf-8')
    }
    
    return jsonify(encrypted_data)

# Decryption Function
@app.route('/decrypt', methods=['POST'])
def decrypt_image():
    # Step 1: Get the encrypted AES key and image data
    encrypted_aes_key = base64.b64decode(request.form['encrypted_aes_key'])
    ciphertext = base64.b64decode(request.form['ciphertext'])
    nonce = base64.b64decode(request.form['nonce'])
    tag = base64.b64decode(request.form['tag'])

    # Step 2: Decrypt the AES key using RSA
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)

    # Step 3: Decrypt the image using AES
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    decrypted_image = cipher_aes.decrypt_and_verify(ciphertext, tag)

    # Return the decrypted image as Base64 (assuming it's a PNG image)
    return jsonify({
        'decrypted_image': base64.b64encode(decrypted_image).decode('utf-8'),
        'mime_type': 'image/png'  # Assuming the image is PNG. Adjust if it's JPEG.
    })

# Render HTML form for image encryption and decryption
@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
