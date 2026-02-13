from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for , Response, flash
from flask_sqlalchemy import SQLAlchemy
import json
import os
from flask import send_from_directory
from werkzeug.utils import secure_filename
import csv
from io import StringIO
from flask import Response
import smtplib
from email.mime.text import MIMEText
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
# Limit upload size to 50MB
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
app.jinja_env.add_extension('jinja2.ext.do') 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'freelancer_platform.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'tm471-project-security-key'
db = SQLAlchemy(app)

# Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return Freelancer.query.get(int(user_id))

# Add these configurations
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- DATABASE MODELS ---

class Freelancer(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    email = db.Column(db.String(120)) # New: To know where to send notifications
    email_app_password = db.Column(db.String(100)) # New: For SMTP authentication
     # Link to multiple forms
    forms = db.relationship('Form', backref='owner', lazy=True)
    requests = db.relationship('ClientRequest', backref='freelancer', lazy=True)
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Form(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), default="Main Intake Form")
    structure = db.Column(db.Text, default='[]')
    brand_color = db.Column(db.String(20), default='#0d6efd') 
    accent_color = db.Column(db.String(20), default='#e9ecef')
    logo_url = db.Column(db.String(200), default='') 
    freelancer_id = db.Column(db.Integer, db.ForeignKey('freelancer.id'), nullable=False)

# Update ClientRequest to link to a specific Form too
class ClientRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    freelancer_id = db.Column(db.Integer, db.ForeignKey('freelancer.id'), nullable=False)
    form_id = db.Column(db.Integer, db.ForeignKey('form.id'), nullable=True) # New
    client_name = db.Column(db.String(100), nullable=False)
    submitted_data = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='New')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Setup Database and create 'Ahmed' as a default user
with app.app_context():
    db.create_all()
    if not Freelancer.query.filter_by(username='Ahmed').first():
        db.session.add(Freelancer(username='Ahmed'))
        db.session.commit()

# --- ROUTES ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')

        # Check if username already exists
        existing_user = Freelancer.query.filter_by(username=username).first()
        if existing_user:
            return "Username already taken!", 400

        # Create new freelancer
        new_user = Freelancer(username=username, email=email)
        new_user.set_password(password) # This hashes it!
        
        db.session.add(new_user)
        db.session.commit()
        
        # Log them in automatically and send to dashboard
        login_user(new_user)
        return redirect(url_for('welcome')) 
    return render_template('register.html')

@app.route('/welcome')
@login_required
def welcome():
    return render_template('welcome.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = Freelancer.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard', username=user.username))
        else:
            flash("Invalid username or password. Please try again.")
            return render_template('login.html'), 401
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index')) # Goes back to landing page

# 0. Admin
@app.route('/admin/stats')
def admin_stats():
    total_users = Freelancer.query.count()
    total_forms = Form.query.count()
    total_requests = ClientRequest.query.count()
    
    # Get the latest 5 submissions across the whole platform
    recent_activity = ClientRequest.query.order_by(ClientRequest.id.desc()).limit(5).all()
    
    return render_template('admin.html', 
                           users=total_users, 
                           forms=total_forms, 
                           reqs=total_requests,
                           activity=recent_activity)

# 1. THE BUILDER (Freelancer creates the form)@app.route('/build/<username>', methods=['GET', 'POST'])
@app.route('/create_form/<username>')
def create_new_form(username):
    user = Freelancer.query.filter_by(username=username).first_or_404()
    new_form = Form(owner=user, name="New Project Form")
    db.session.add(new_form)
    db.session.commit()
    return redirect(url_for('build_form', username=username, form_id=new_form.id))

@app.route('/build/<username>/<int:form_id>', methods=['GET', 'POST'])
def build_form(username, form_id):
    user = Freelancer.query.filter_by(username=username).first_or_404()
    form_obj = Form.query.get_or_404(form_id)
    
    if request.method == 'POST':
        labels = request.form.getlist('q_label')
        types = request.form.getlist('q_type')
        logics = request.form.getlist('q_logic')
        sections = request.form.getlist('q_section_ref')
        options = request.form.getlist('q_options') # Added this
        reqs = request.form.getlist('q_required')
        
        structure = []
        for i in range(len(labels)):
            structure.append({
                "label": labels[i],
                "type": types[i],
                "logic": logics[i],
                "section": sections[i] if i < len(sections) else "General",
                "options": options[i] if i < len(options) else "",
                'required': reqs[i] == "1"
            })
            
        form_obj.name = request.form.get('form_name') # Allow naming the form
        form_obj.structure = json.dumps(structure)
        form_obj.brand_color = request.form.get('brand_color')
        form_obj.accent_color = request.form.get('accent_color')
        form_obj.logo_url = request.form.get('logo_url')
        
        
        db.session.commit()
        return redirect(url_for('dashboard', username=username))
    
    fields = json.loads(form_obj.structure or '[]')
    return render_template('builder.html', user=user, form_obj=form_obj, fields=fields)

@app.route('/delete_form/<int:form_id>', methods=['POST'])
@login_required
def delete_form(form_id):
    form_to_delete = Form.query.get_or_404(form_id)
    
    # Security: Ensure this form actually belongs to the logged-in user
    if form_to_delete.freelancer_id != current_user.id:
        return "Unauthorized", 403
        
    db.session.delete(form_to_delete)
    db.session.commit()
    return redirect(url_for('dashboard', username=current_user.username))


# 2. THE PUBLIC URL (Client fills the form)
@app.route('/share/<username>/<int:form_id>')
def public_form(username, form_id):
    user = Freelancer.query.filter_by(username=username).first_or_404()
    form_obj = Form.query.get_or_404(form_id)
    fields = json.loads(form_obj.structure)
    return render_template('public_form.html', user=user, fields=fields, form_obj=form_obj)

# 3. SUBMISSION LOGIC
@app.route('/submit/<int:user_id>/<int:form_id>', methods=['POST'])
def submit_request(user_id, form_id):
    client_name = request.form.get('client_name')
    answers = {key: value for key, value in request.form.items() if key != 'client_name'}
    raw_data = request.form.to_dict(flat=False)
    answers = {}

    # Validation
    if not client_name or len(client_name.strip()) < 2:
        return "<h3>Error: Please enter a valid Name.</h3><a href='javascript:history.back()'>Go Back</a>", 400
    
    for key, value in raw_data.items():
        if key == 'client_name': continue
        # If it's a list with one item, save as string. If multiple, join with commas.
        answers[key.replace('[]', '')] = ", ".join(value) if len(value) > 1 else value[0]
    # Handle File Uploads
    for field_name, file in request.files.items():
        if file and file.filename != '':
            filename = secure_filename(f"{user_id}_{field_name}_{file.filename}")
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            answers[field_name] = f"FILE:{filename}" # Mark as file for the dashboard
    
    user = Freelancer.query.get(user_id)
    form_obj = Form.query.get_or_404(form_id)
    structure = json.loads(form_obj.structure)

    new_request = ClientRequest(
        freelancer_id=user_id,
        form_id=form_id,
        client_name=client_name,
        submitted_data=json.dumps(answers)
    )
    
    # Validation Loop
    for field in structure:
        if field.get('required'):
            val = request.form.get(field['label'])
            # Check if text is empty OR file is missing
            if not val or val.strip() == "":
                # Also check files if it's a file field
                if field['type'] == 'file' and field['label'] not in request.files:
                     return f"<h3>Error: The field '{field['label']}' is required.</h3>", 400

    db.session.add(new_request)
    db.session.commit()
    submission_ref = f"REQ-{new_request.id:05d}"
    # FR-TF.04: Trigger Real-time Notification
    send_notification_email(user, client_name, form_obj.name)

    return f"""
    <div style="background-color: {form_obj.accent_color}; height: 100vh; display: flex; align-items: center; justify-content: center; font-family: sans-serif;">
        <div style="background: white; padding: 40px; border-radius: 20px; box-shadow: 0 10px 25px rgba(0,0,0,0.1); text-align: center; border-top: 10px solid {form_obj.brand_color};">
            <h1 style="color: {form_obj.brand_color};">Success!</h1>
            <p>Thank you, <strong>{client_name}</strong>. Your request has been sent.</p>
            <div style="margin: 20px 0; padding: 15px; background: #f8f9fa; border: 1px dashed #ccc; border-radius: 10px;">
                <small style="color: #666; display: block; margin-bottom: 5px;">SUBMISSION ID</small>
                <strong style="font-size: 1.5rem; letter-spacing: 2px;">{submission_ref}</strong>
            </div>
            <p style="font-size: 0.9rem; color: #777;">A notification has been sent to the freelancer.</p>
            <a href="/" style="display: inline-block; margin-top: 20px; color: {form_obj.brand_color}; text-decoration: none; font-weight: bold;">← Return Home</a>
        </div>
    </div>
    """

# 4. THE DASHBOARD (Notifications)
@app.route('/dashboard/<username>')
@login_required
def dashboard(username):
    # Security check: Make sure the logged-in user is actually 'username'
    if current_user.username.lower() != username.lower():
        return "Unauthorized access - You cannot view another editor's dashboard.", 403

    user = Freelancer.query.filter_by(username=username).first_or_404()
    requests = ClientRequest.query.filter_by(freelancer_id=user.id).order_by(ClientRequest.id.desc()).all()
    return render_template('dashboard.html', user=user, requests=requests)

@app.route('/delete_request/<int:request_id>', methods=['POST'])
def delete_request(request_id):
    req = ClientRequest.query.get_or_404(request_id)
    username = req.freelancer.username # Get username to redirect back to dashboard
    db.session.delete(req)
    db.session.commit()
    return redirect(url_for('dashboard', username=username))

@app.template_filter('list_from_json')
def list_from_json(json_data):
    try:
        # If it's already a dict, return it; otherwise parse it
        if isinstance(json_data, dict):
            return json_data
        return json.loads(json_data)
    except (ValueError, TypeError):
        return {}
    
@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/update_status/<int:request_id>', methods=['POST'])
def update_status(request_id):
    req = ClientRequest.query.get_or_404(request_id)
    new_status = request.form.get('status')
    req.status = new_status
    db.session.commit()
    return redirect(url_for('dashboard', username=req.freelancer.username))

#5. Export
@app.route('/export/<username>')
def export_data(username):
    user = Freelancer.query.filter_by(username=username).first_or_404()
    requests = ClientRequest.query.filter_by(freelancer_id=user.id).all()

    def generate():
        data = StringIO()
        writer = csv.writer(data)
        
        # Header row
        writer.writerow(['Request ID', 'Client Name', 'Form ID', 'Status', 'Submitted Data'])
        
        for req in requests:
            # Flatten the JSON data into a readable string for Excel
            readable_data = ""
            try:
                decoded = json.loads(req.submitted_data)
                readable_data = " | ".join([f"{k}: {v}" for k, v in decoded.items()])
            except:
                readable_data = req.submitted_data

            writer.writerow([req.id, req.client_name, req.form_id, req.status, readable_data])
            yield data.getvalue()
            data.seek(0)
            data.truncate(0)

    response = Response(generate(), mimetype='text/csv')
    response.headers.set("Content-Disposition", "attachment", filename=f"{username}_submissions.csv")
    return response

# Mail 
def send_notification_email(freelancer,client_name,form_name):
    if not freelancer.email or not freelancer.email_app_password:
        print("Email skipped: Credentials not set.")
        return
    
    msg = MIMEText(f"Hello {freelancer.username},\n\nYou have a new project request from {client_name} via your '{form_name}' form \n\nView it on your dashboard: http://localhost:5001/dashboard/{freelancer.username}")
    msg['Subject'] = f"🔔 New Project Request: {client_name}"
    msg['From'] = freelancer.email
    msg['To'] = freelancer.email

    try:
        # Example for Gmail. Use 'smtp.office365.com' for Outlook
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(freelancer.email, freelancer.email_app_password)
            server.send_message(msg)
        print("Real-time email sent!")
    except Exception as e:
        print(f"Email Error: {e}")

@app.route('/update_settings/<username>', methods=['POST'])
def update_settings(username):
    user = Freelancer.query.filter_by(username=username).first_or_404()
    
    # Update the notification credentials
    user.email = request.form.get('freelancer_email')
    user.email_app_password = request.form.get('email_password')
    
    db.session.commit()
    # Flash a message if you have flashing enabled, or just redirect
    return redirect(url_for('dashboard', username=username))

if __name__ == '__main__':
    app.run(debug=True, port=5001)