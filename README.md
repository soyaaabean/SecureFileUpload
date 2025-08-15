# SecureFileUpload
A secure file upload and management web application built with Flask. Users can register, log in, upload files, and download their own files. The application uses CSRF protection using Flask-WTF for forms, Flask-Login for authentication, basic XSS mitigation via security headers and planned Content Security Policy, and SQLAlchemy as the ORM (Object-Relational Mapper) for SQLite.

# Features
- User registration and login with password hashing
- Secure session management
- File uploads with random file names to protect privacy
- File type restrictions (pdf, png, jpg, jpeg, txt)
- File size limit of 5 MB
- Users can only access their own files
- Flash messages for upload success/error
- Basic security headers implemented
- Dashboard showing uploaded files and upload form

# How to Run
1. Clone the repository
```bash
git clone https://github.com/soyaaabean/SecureFileUpload.git
cd SecureFileUpload
```
2. Create a virtual environment and activate it
```bash
python -m venv .venv
source .venv/bin/activate   # macOS/Linux
.venv\Scripts\activate      # Windows
```
3. Install dependencies
```bash
pip install -r requirements.txt
```
4. Create a .env file with the following required environments variables
```bash
SECRET_KEY=your_super_secret_key  # Change this to a randmom hex string (could generate using: python -c "import secrets; print(secrets.token_hex(32))")
DATABASE_URL=sqlite:///database.db
```
5. Run the app :>
```bash
flask run  # Should be running on https://127.0.0.1:5000
```
NOTE: Before running, create an uploads/ folder in the project root.

# What to Expect
- Register a new user and log in.
- Upload files from the dashboard.
- Download your files from the file list.
- Files are stored securely in the uploads folder with randomized names.
<img width="902" height="450" alt="Screenshot 2025-08-15 at 9 54 48 PM" src="https://github.com/user-attachments/assets/8b0bfaa0-4a8b-41db-a333-a0fd3f02d9bd" />
<img width="902" height="450" alt="Screenshot 2025-08-15 at 9 55 45 PM" src="https://github.com/user-attachments/assets/a1c6516c-6b85-4fa3-980b-0eba831d3f3b" />
<img width="902" height="450" alt="Screenshot 2025-08-15 at 10 03 29 PM" src="https://github.com/user-attachments/assets/ea786020-3eb2-4007-91d0-413ac85d6b28" />
<img width="902" height="450" alt="Screenshot 2025-08-15 at 10 04 12 PM" src="https://github.com/user-attachments/assets/41ab0d4e-0feb-4026-9334-8a5de0fde8b2" />

# Security Additions
- Only registered users can access their files.
- Passwords are hashed with Werkzeug.
- Maximum upload size: 5 MB.
- Allowed file types: PDF, PNG, JPG, JPEG, TXT.
- Basic security headers (X-Content-Type-Options, X-Frame-Options) along with XSS mitigation and planned Content Security Policy are set.

## Author

This project was developed as part of personal projects

## License

This code is provided for educational purposes. You are free to modify and reuse it for non-commercial use.



