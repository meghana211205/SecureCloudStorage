import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from config import Config
from models import db, User, File
from crypto.rsa_util import generate_keys, encrypt_aes_key, decrypt_aes_key
from crypto.aes_util import encrypt_file, decrypt_file, encrypt_file_with_key
from crypto.kem_util import generate_kem_keys, encapsulate_key_kem, decapsulate_key_kem
from crypto.hash_util import generate_hash
import uuid

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize extensions
    db.init_app(app)

    # Ensure upload folder exists
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    with app.app_context():
        # Create database tables for our data models
        db.create_all()

    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')

            if User.query.filter_by(username=username).first():
                flash('Username already exists.', 'danger')
                return redirect(url_for('register'))

            # Hash the password
            hashed_password = generate_password_hash(password)
            
            # Generate RSA Keys for the user
            private_key, public_key = generate_keys()

            # Generate ML-KEM Keys
            kem_public_key, kem_private_key = generate_kem_keys()

            # Create new user
            new_user = User(
                username=username, 
                password_hash=hashed_password,
                public_key=public_key,
                private_key=private_key,
                kem_public_key=kem_public_key,
                kem_private_key=kem_private_key
            )
            db.session.add(new_user)
            db.session.commit()

            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))

        return render_template('register.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')

            user = User.query.filter_by(username=username).first()

            if user and check_password_hash(user.password_hash, password):
                session['user_id'] = user.id
                session['username'] = user.username
                flash('Logged in successfully.', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password.', 'danger')

        return render_template('login.html')

    @app.route('/logout')
    def logout():
        session.pop('user_id', None)
        session.pop('username', None)
        flash('You have been logged out.', 'success')
        return redirect(url_for('index'))

    @app.route('/dashboard')
    def dashboard():
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login'))
        
        user_files = File.query.filter_by(owner_id=session['user_id']).all()
        return render_template('dashboard.html', username=session['username'], files=user_files)

    @app.route('/upload', methods=['POST'])
    def upload():
        if 'user_id' not in session:
            return redirect(url_for('login'))
            
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
            
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(url_for('dashboard'))
            
        if file:
            filename = secure_filename(file.filename)
            file_bytes = file.read()
            
            # 1. Generate SHA-256 Hash of original file
            file_hash = generate_hash(file_bytes)
            
            user = User.query.get(session['user_id'])
            algo = request.form.get('encryption_algo')
            
            if not algo:
                flash('Please select an encryption algorithm.', 'danger')
                return redirect(url_for('dashboard'))

            # 2 & 3. Encrypt File and Generate/Wrap Key
            if algo == 'ML-KEM':
                aes_key, encrypted_aes_key = encapsulate_key_kem(user.kem_public_key)
                ciphertext, nonce, tag = encrypt_file_with_key(file_bytes, aes_key)
            else:
                ciphertext, nonce, tag, aes_key = encrypt_file(file_bytes)
                encrypted_aes_key = encrypt_aes_key(aes_key, user.public_key)
            
            # 4. Save Encrypted File to disk
            unique_storage_name = f"{uuid.uuid4().hex}_{filename}.enc"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_storage_name)
            
            with open(file_path, 'wb') as f:
                # Store nonce and tag with ciphertext for AES-GCM
                f.write(nonce + tag + ciphertext)
                
            # 5. Save metadata to DB
            new_file = File(
                owner_id=user.id,
                filename=filename,
                file_path=file_path,
                encrypted_aes_key=encrypted_aes_key,
                sha256_hash=file_hash,
                encryption_algo=algo
            )
            db.session.add(new_file)
            db.session.commit()
            
            flash('File uploaded and encrypted successfully.', 'success')
            return redirect(url_for('dashboard'))

    @app.route('/download/<int:file_id>')
    def download(file_id):
        if 'user_id' not in session:
            return redirect(url_for('login'))
            
        file_record = File.query.get_or_404(file_id)
        
        # Ensure user owns the file
        if file_record.owner_id != session['user_id']:
            flash('Unauthorized access.', 'danger')
            return redirect(url_for('dashboard'))
            
        user = User.query.get(session['user_id'])
        
        # 1. Read encrypted file from disk
        try:
            with open(file_record.file_path, 'rb') as f:
                file_data = f.read()
            
            # Extract nonce (16 bytes), tag (16 bytes), and ciphertext
            nonce = file_data[:16]
            tag = file_data[16:32]
            ciphertext = file_data[32:]
            
            # 2. Decrypt AES key based on algorithm
            if file_record.encryption_algo == 'ML-KEM':
                aes_key = decapsulate_key_kem(file_record.encrypted_aes_key, user.kem_private_key)
            else:
                aes_key = decrypt_aes_key(file_record.encrypted_aes_key, user.private_key)
            
            # 3. Decrypt file using AES key
            plaintext = decrypt_file(ciphertext, aes_key, nonce, tag)
            
            # 4. Verify Integrity
            decrypted_hash = generate_hash(plaintext)
            if decrypted_hash != file_record.sha256_hash:
                flash('File integrity verification failed!', 'danger')
                return redirect(url_for('dashboard'))
                
            # 5. Send decrypted file to user
            temp_path = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_{file_record.filename}")
            with open(temp_path, 'wb') as f:
                f.write(plaintext)
                
            return send_file(temp_path, as_attachment=True, download_name=file_record.filename)
            
        except Exception as e:
            flash(f'Error downloading file: {str(e)}', 'danger')
            return redirect(url_for('dashboard'))

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, port=5000)
