from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    private_key = db.Column(db.Text, nullable=False)
    kem_public_key = db.Column(db.LargeBinary, nullable=False)
    kem_private_key = db.Column(db.LargeBinary, nullable=False)

    # Relationships
    files = db.relationship('File', backref='owner', lazy=True)
    shared_files = db.relationship('SharedFile', backref='shared_with', lazy=True)

class File(db.Model):
    __tablename__ = 'files'
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(512), nullable=False)
    encrypted_aes_key = db.Column(db.LargeBinary, nullable=False)
    sha256_hash = db.Column(db.String(64), nullable=False)
    encryption_algo = db.Column(db.String(20), nullable=False, default='RSA')

    # Relationship for shares
    shares = db.relationship('SharedFile', backref='file', lazy=True)

class SharedFile(db.Model):
    __tablename__ = 'shared_files'
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('files.id'), nullable=False)
    shared_with_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    encrypted_aes_key = db.Column(db.LargeBinary, nullable=False)
