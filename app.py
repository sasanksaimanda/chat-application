from flask import Flask, render_template, request, redirect, url_for, session, send_file, jsonify, flash
from pymongo import MongoClient
import bcrypt
from bson import ObjectId
import os
from werkzeug.utils import secure_filename
from datetime import datetime
import re

# Add Caesar cipher functions
def caesar_encrypt(text, shift=3):
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
        else:
            result += char
    return result

def caesar_decrypt(text, shift=3):
    return caesar_encrypt(text, -shift)

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a secure secret key

# MongoDB connection setup
client = MongoClient('mongodb://localhost:27017/')
db = client['clinetchat_application']

# Collections
users_collection = db['users']
contacts_collection = db['contacts']
messages_collection = db['messages']

# Directory to store uploaded files
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'mp4', 'avi'}

# Trusted domains
TRUSTED_DOMAINS = ['facebook.com', 'google.com', 'instagram.com', 'youtube.com', 'twitter.com']

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_trusted_link(url):
    return any(domain in url for domain in TRUSTED_DOMAINS)

def detect_links(message):
    url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
    links = url_pattern.findall(message)
    return links

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        mobile = request.form['mobile']
        password = request.form['password']
        name = request.form['name']

        # Check if user already exists
        existing_user = users_collection.find_one({'user_id': mobile})
        if existing_user:
            flash('Mobile number already registered. Please login or use a different number.', 'error')
            return redirect(url_for('signup'))

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Encrypt the name
        encrypted_name = caesar_encrypt(name)

        # Insert user data into the users collection
        users_collection.insert_one({'user_id': mobile, 'password': hashed_password, 'name': encrypted_name})

        # Create an empty contacts list for the new user
        contacts_collection.insert_one({'user_id': mobile, 'contacts': []})

        flash('Account created successfully. Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        mobile = request.form['mobile']
        password = request.form['password']

        # Check if user exists in the users collection
        user = users_collection.find_one({'user_id': mobile})
        
        if user:
            if bcrypt.checkpw(password.encode('utf-8'), user['password']):
                session['user_id'] = mobile
                session['username'] = caesar_decrypt(user['name'])
                return redirect(url_for('chat'))
            else:
                flash('Invalid password. Please try again.', 'error')
        else:
            flash('User not found. Please check your mobile number or sign up.', 'error')

    return render_template('login.html')

@app.route('/chat', methods=['GET', 'POST'])
def chat():
    if 'user_id' in session:
        username = session.get('username')
        user_id = session.get('user_id')

        # Get user's contacts
        user_contacts = contacts_collection.find_one({'user_id': user_id})
        if user_contacts:
            contacts = list(users_collection.find({'user_id': {'$in': user_contacts['contacts']}}))
        else:
            contacts = []

        # Get all users except the current user
        all_users = list(users_collection.find({'user_id': {'$ne': user_id}}))

        selected_contact = request.args.get('contact_id')
        chat_history = []

        if selected_contact:
            chat_history = list(messages_collection.find({
                '$or': [
                    {'sender': user_id, 'receiver': selected_contact},
                    {'sender': selected_contact, 'receiver': user_id}
                ]
            }).sort('timestamp', 1))

            # Process messages to detect and handle links
            for msg in chat_history:
                msg['is_sender'] = msg['sender'] == user_id
                if msg.get('message'):
                    msg['message'] = caesar_decrypt(msg['message'])
                    links = detect_links(msg['message'])
                    msg['links'] = []
                    for link in links:
                        msg['links'].append({
                            'url': link,
                            'trusted': is_trusted_link(link)
                        })

        return render_template('chat.html', username=username, contacts=contacts, all_users=all_users, chat_history=chat_history, selected_contact=selected_contact)
    else:
        return redirect(url_for('login'))

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'user_id' in session:
        sender = session['user_id']
        receiver = request.form['receiver']
        message = request.form.get('message')
        file = request.files.get('file')

        # Encrypt the message
        encrypted_message = caesar_encrypt(message) if message else None

        message_data = {
            'sender': sender,
            'receiver': receiver,
            'timestamp': datetime.now(),
            'message': encrypted_message,
            'file_path': None
        }

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            message_data['file_path'] = file_path

        # Detect and handle links
        if message:
            links = detect_links(message)
            message_data['links'] = []
            for link in links:
                message_data['links'].append({
                    'url': link,
                    'trusted': is_trusted_link(link)
                })

        # Save message to messages collection
        messages_collection.insert_one(message_data)

        # Add receiver to sender's contacts if not already present
        contacts_collection.update_one(
            {'user_id': sender},
            {'$addToSet': {'contacts': receiver}}
        )

        # Add sender to receiver's contacts if not already present
        contacts_collection.update_one(
            {'user_id': receiver},
            {'$addToSet': {'contacts': sender}}
        )

        return redirect(url_for('chat', contact_id=receiver))

@app.route('/add_contact', methods=['POST'])
def add_contact():
    if 'user_id' in session:
        user_id = session['user_id']
        contact_id = request.form['contact_id']

        # Check if the contact exists in the users collection
        contact_user = users_collection.find_one({'user_id': contact_id})
        if not contact_user:
            return jsonify({'status': 'error', 'message': 'User not found'})

        # Add contact to user's contact list
        result = contacts_collection.update_one(
            {'user_id': user_id},
            {'$addToSet': {'contacts': contact_id}}
        )

        if result.modified_count > 0 or result.matched_count > 0:
            return jsonify({'status': 'success'})
        else:
            return jsonify({'status': 'error', 'message': 'Failed to add contact'})

    return jsonify({'status': 'error', 'message': 'User not logged in'})

@app.route('/block_contact', methods=['POST'])
def block_contact():
    if 'user_id' in session:
        user_id = session['user_id']
        contact_id = request.form['contact_id']

        # Remove contact from user's contact list
        result = contacts_collection.update_one(
            {'user_id': user_id},
            {'$pull': {'contacts': contact_id}}
        )

        if result.modified_count > 0:
            return jsonify({'status': 'success'})
        else:
            return jsonify({'status': 'error', 'message': 'Contact not found or already blocked'})

    return jsonify({'status': 'error', 'message': 'User not logged in'})

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/download/<file_id>')
def download_file(file_id):
    file_record = messages_collection.find_one({'_id': ObjectId(file_id)})
    if file_record and file_record.get('file_path'):
        return send_file(file_record['file_path'], as_attachment=True)
    return 'File not found.', 404

if __name__ == '__main__':
    app.run(debug=True)