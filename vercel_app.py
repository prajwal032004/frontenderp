"""
VERCEL FRONTEND APP (vercel_app.py)
====================================
This app runs on Vercel and ONLY handles:
- Template rendering
- Session management (using secure cookies)
- Forwarding requests to backend API
- NO database operations
- NO file storage
- NO business logic

Environment Variables Required:
- BACKEND_API_URL: URL of backend API (e.g., https://yourapp.pythonanywhere.com)
- BACKEND_API_KEY: Secret key for authenticating with backend
- SECRET_KEY: Flask session secret
"""

import os
import requests
from functools import wraps
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

app = Flask(__name__, template_folder='templates', static_folder='static')

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-this-in-production')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=365)
app.config['SESSION_COOKIE_SECURE'] = True  
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

BACKEND_URL = os.environ.get('BACKEND_API_URL', 'http://localhost:5001')
BACKEND_API_KEY = os.environ.get('BACKEND_API_KEY', 'your-secret-api-key')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.session_protection = 'basic'

def get_api_headers(include_auth=True):
    headers = {
        'Content-Type': 'application/json',
        'X-API-Key': BACKEND_API_KEY
    }
    return headers

def api_request(method, endpoint, data=None, files=None, user_id=None):
    """Make request to backend API"""
    url = f"{BACKEND_URL}{endpoint}"
    headers = get_api_headers()
    
    # Add user ID to headers if provided
    if user_id:
        headers['X-User-ID'] = str(user_id)
    
    try:
        if method == 'GET':
            response = requests.get(url, headers=headers, params=data, timeout=30)
        elif method == 'POST':
            if files:
                headers.pop('Content-Type', None)
                response = requests.post(url, headers=headers, data=data, files=files, timeout=60)
            else:
                response = requests.post(url, headers=headers, json=data, timeout=30)
        elif method == 'PUT':
            response = requests.put(url, headers=headers, json=data, timeout=30)
        elif method == 'DELETE':
            response = requests.delete(url, headers=headers, timeout=30)
        else:
            return {'success': False, 'error': 'Invalid method'}
        
        if response.status_code == 200:
            return response.json()
        else:
            return {'success': False, 'error': f'API Error: {response.status_code}', 'details': response.text}
    
    except requests.exceptions.Timeout:
        return {'success': False, 'error': 'Backend API timeout'}
    except requests.exceptions.ConnectionError:
        return {'success': False, 'error': 'Cannot connect to backend API'}
    except Exception as e:
        return {'success': False, 'error': str(e)}
# ============================================================================
# USER CLASS (Minimal - no DB)
# ============================================================================

class User(UserMixin):
    def __init__(self, user_data):
        self.id = user_data['id']
        self.intern_id = user_data.get('intern_id')
        self.usn = user_data.get('usn')
        self.full_name = user_data.get('full_name')
        self.email = user_data.get('email')
        self.role = user_data.get('role')
        self.status = user_data.get('status')
        self.is_admin = bool(user_data.get('is_admin'))
        self.photo_url = user_data.get('photo_url')
        self.department = user_data.get('department')

@login_manager.user_loader
def load_user(user_id):
    """Load user from backend API"""
    result = api_request('GET', f'/api/users/{user_id}')
    if result.get('success') and result.get('user'):
        return User(result['user'])
    return None

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def approved_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        if current_user.status != 'APPROVED' and not current_user.is_admin:
            return render_template('auth/pending.html')
        return f(*args, **kwargs)
    return decorated_function

# ============================================================================
# SESSION MANAGEMENT
# ============================================================================

@app.before_request
def make_session_permanent():
    session.permanent = True

# ============================================================================
# PUBLIC ROUTES
# ============================================================================

@app.route('/')
def index():
    result = api_request('GET', '/api/public/stats')
    if result.get('success'):
        return render_template('public/index.html', **result['data'])
    return render_template('public/index.html')

@app.route('/about')
def about():
    return render_template('public/about.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        data = {
            'name': request.form.get('name'),
            'email': request.form.get('email'),
            'message': request.form.get('message')
        }
        result = api_request('POST', '/api/public/contact', data)
        if result.get('success'):
            flash('Thank you for contacting us! We will get back to you soon.', 'success')
        else:
            flash('Error sending message. Please try again.', 'error')
        return redirect(url_for('contact'))
    return render_template('public/contact.html')

@app.route('/terms')
def terms():
    return render_template('public/terms.html')

@app.route('/privacy')
def privacy():
    return render_template('public/privacy.html')

# ============================================================================
# AUTHENTICATION ROUTES
# ============================================================================

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = {
            'usn': request.form.get('usn'),
            'full_name': request.form.get('full_name'),
            'phone': request.form.get('phone'),
            'email': request.form.get('email'),
            'password': request.form.get('password'),
            'role': request.form.get('role'),
            'department': request.form.get('department'),
            'photo_data': request.form.get('photo_data')
        }
        
        result = api_request('POST', '/api/auth/register', data)
        
        if result.get('success'):
            flash(result.get('message', 'Registration successful!'), 'success')
            return redirect(url_for('login'))
        else:
            flash(result.get('error', 'Registration failed'), 'error')
            return redirect(url_for('register'))
    
    return render_template('auth/register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('intern_dashboard'))
    
    if request.method == 'POST':
        data = {
            'email': request.form.get('email'),
            'password': request.form.get('password'),
            'remember': request.form.get('remember', False)
        }
        
        result = api_request('POST', '/api/auth/login', data)
        
        if result.get('success'):
            user = User(result['user'])
            login_user(user, remember=data['remember'])
            
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            elif user.status == 'APPROVED':
                return redirect(url_for('intern_dashboard'))
            else:
                return render_template('auth/pending.html')
        else:
            flash(result.get('error', 'Invalid credentials'), 'error')
    
    return render_template('auth/login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('index'))

# ============================================================================
# ADMIN ROUTES
# ============================================================================

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    result = api_request('GET', '/api/admin/dashboard')
    if result.get('success'):
        return render_template('admin/dashboard.html', **result['data'])
    flash('Error loading dashboard', 'error')
    return redirect(url_for('index'))

@app.route('/admin/interns')
@login_required
@admin_required
def admin_interns():
    params = {
        'role': request.args.get('role', 'all'),
        'status': request.args.get('status', 'all'),
        'department': request.args.get('department', 'all'),
        'search': request.args.get('search', '')
    }
    result = api_request('GET', '/api/admin/interns', params)
    if result.get('success'):
        return render_template('admin/interns.html', **result['data'])
    return render_template('admin/interns.html', interns=[])

@app.route('/admin/intern/<int:intern_id>')
@login_required
@admin_required
def admin_intern_detail(intern_id):
    result = api_request('GET', f'/api/admin/intern/{intern_id}')
    if result.get('success'):
        return render_template('admin/intern_detail.html', **result['data'])
    flash('Intern not found', 'error')
    return redirect(url_for('admin_interns'))

@app.route('/admin/approvals')
@login_required
@admin_required
def admin_approvals():
    result = api_request('GET', '/api/admin/approvals')
    if result.get('success'):
        return render_template('admin/approvals.html', **result['data'])
    return render_template('admin/approvals.html', pending_interns=[])

@app.route('/admin/approve/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def approve_intern(user_id):
    result = api_request('POST', f'/api/admin/approve/{user_id}')
    if result.get('success'):
        flash('Intern approved successfully!', 'success')
    else:
        flash(result.get('error', 'Approval failed'), 'error')
    return redirect(url_for('admin_approvals'))

@app.route('/admin/reject/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def reject_intern(user_id):
    result = api_request('POST', f'/api/admin/reject/{user_id}')
    if result.get('success'):
        flash('Intern rejected.', 'info')
    else:
        flash(result.get('error', 'Rejection failed'), 'error')
    return redirect(url_for('admin_approvals'))

@app.route('/admin/attendance')
@login_required
@admin_required
def admin_attendance():
    params = {'date': request.args.get('date', '')}
    result = api_request('GET', '/api/admin/attendance', params)
    if result.get('success'):
        return render_template('admin/attendance.html', **result['data'])
    return render_template('admin/attendance.html')

@app.route('/admin/attendance/export-csv')
@login_required
@admin_required
def export_attendance_csv():
    month = request.args.get('month', '')
    result = api_request('GET', f'/api/admin/attendance/export-csv?month={month}')
    if result.get('success') and result.get('csv_url'):
        return redirect(result['csv_url'])
    flash('Export failed', 'error')
    return redirect(url_for('admin_attendance'))

@app.route('/admin/attendance/export-summary-csv')
@login_required
@admin_required
def export_attendance_summary_csv():
    month = request.args.get('month', '')
    result = api_request('GET', f'/api/admin/attendance/export-summary-csv?month={month}')
    if result.get('success') and result.get('csv_url'):
        return redirect(result['csv_url'])
    flash('Export failed', 'error')
    return redirect(url_for('admin_attendance'))

@app.route('/admin/tasks', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_tasks():
    if request.method == 'POST':
        data = {
            'title': request.form.get('title'),
            'description': request.form.get('description'),
            'assigned_to': request.form.get('assigned_to'),
            'deadline': request.form.get('deadline'),
            'priority': request.form.get('priority'),
            'category': request.form.get('category'),
            'estimated_hours': request.form.get('estimated_hours'),
            'file_data': request.form.get('file_data')
        }
        result = api_request('POST', '/api/admin/tasks/create', data)
        if result.get('success'):
            flash('Task created successfully!', 'success')
        else:
            flash(result.get('error', 'Task creation failed'), 'error')
        return redirect(url_for('admin_tasks'))
    
    result = api_request('GET', '/api/admin/tasks')
    if result.get('success'):
        return render_template('admin/tasks.html', **result['data'])
    return render_template('admin/tasks.html', tasks=[])

@app.route('/admin/task/<int:task_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_task(task_id):
    result = api_request('DELETE', f'/api/admin/tasks/{task_id}')
    if result.get('success'):
        flash('Task deleted successfully!', 'success')
    else:
        flash(result.get('error', 'Deletion failed'), 'error')
    return redirect(url_for('admin_tasks'))

@app.route('/admin/task/<int:task_id>/update', methods=['POST'])
@login_required
@admin_required
def update_task(task_id):
    data = {
        'status': request.form.get('status'),
        'completion_percentage': request.form.get('completion_percentage')
    }
    result = api_request('PUT', f'/api/admin/tasks/{task_id}', data)
    if result.get('success'):
        flash('Task updated successfully!', 'success')
    else:
        flash(result.get('error', 'Update failed'), 'error')
    return redirect(url_for('admin_tasks'))

@app.route('/admin/submissions')
@login_required
@admin_required
def admin_submissions():
    params = {'status': request.args.get('status', 'PENDING')}
    result = api_request('GET', '/api/admin/submissions', params)
    if result.get('success'):
        return render_template('admin/submissions.html', **result['data'])
    return render_template('admin/submissions.html', submissions=[])

@app.route('/admin/submission/<int:submission_id>/approve', methods=['POST'])
@login_required
@admin_required
def approve_submission(submission_id):
    data = {
        'feedback': request.form.get('feedback', ''),
        'grade': request.form.get('grade', 'A')
    }
    result = api_request('POST', f'/api/admin/submissions/{submission_id}/approve', data)
    if result.get('success'):
        flash('Submission approved!', 'success')
    else:
        flash(result.get('error', 'Approval failed'), 'error')
    return redirect(url_for('admin_submissions'))

@app.route('/admin/submission/<int:submission_id>/reject', methods=['POST'])
@login_required
@admin_required
def reject_submission(submission_id):
    data = {'feedback': request.form.get('feedback', '')}
    result = api_request('POST', f'/api/admin/submissions/{submission_id}/reject', data)
    if result.get('success'):
        flash('Submission rejected.', 'info')
    else:
        flash(result.get('error', 'Rejection failed'), 'error')
    return redirect(url_for('admin_submissions'))

@app.route('/admin/document-verification')
@login_required
@admin_required
def admin_document_verification():
    params = {'status': request.args.get('status', 'PENDING')}
    result = api_request('GET', '/api/admin/documents', params)
    if result.get('success'):
        return render_template('admin/document_verification.html', **result['data'])
    return render_template('admin/document_verification.html', documents=[])

@app.route('/admin/document/<int:doc_id>/verify', methods=['POST'])
@login_required
@admin_required
def verify_document(doc_id):
    result = api_request('POST', f'/api/admin/documents/{doc_id}/verify')
    if result.get('success'):
        flash('Document verified!', 'success')
    else:
        flash(result.get('error', 'Verification failed'), 'error')
    return redirect(url_for('admin_document_verification'))

@app.route('/admin/document/<int:doc_id>/reject', methods=['POST'])
@login_required
@admin_required
def reject_document(doc_id):
    data = {'reason': request.form.get('reason', '')}
    result = api_request('POST', f'/api/admin/documents/{doc_id}/reject', data)
    if result.get('success'):
        flash('Document rejected.', 'info')
    else:
        flash(result.get('error', 'Rejection failed'), 'error')
    return redirect(url_for('admin_document_verification'))

@app.route('/admin/performance-reviews', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_performance_reviews():
    if request.method == 'POST':
        data = {
            'user_id': request.form.get('user_id'),
            'review_period': request.form.get('review_period'),
            'technical_skills': request.form.get('technical_skills'),
            'communication': request.form.get('communication'),
            'teamwork': request.form.get('teamwork'),
            'punctuality': request.form.get('punctuality'),
            'strengths': request.form.get('strengths'),
            'improvements': request.form.get('improvements'),
            'comments': request.form.get('comments')
        }
        result = api_request('POST', '/api/admin/performance-reviews', data)
        if result.get('success'):
            flash('Performance review submitted!', 'success')
        else:
            flash(result.get('error', 'Submission failed'), 'error')
        return redirect(url_for('admin_performance_reviews'))
    
    result = api_request('GET', '/api/admin/performance-reviews')
    if result.get('success'):
        return render_template('admin/performance_reviews.html', **result['data'])
    return render_template('admin/performance_reviews.html', reviews=[], interns=[])

@app.route('/admin/announcements', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_announcements():
    if request.method == 'POST':
        data = {
            'title': request.form.get('title'),
            'content': request.form.get('content'),
            'priority': request.form.get('priority', 'NORMAL'),
            'category': request.form.get('category'),
            'target_roles': request.form.get('target_roles', 'ALL'),
            'expires_at': request.form.get('expires_at')
        }
        result = api_request('POST', '/api/admin/announcements', data)
        if result.get('success'):
            flash('Announcement created successfully!', 'success')
        else:
            flash(result.get('error', 'Creation failed'), 'error')
        return redirect(url_for('admin_announcements'))
    
    result = api_request('GET', '/api/admin/announcements')
    if result.get('success'):
        return render_template('admin/announcements.html', **result['data'])
    return render_template('admin/announcements.html', announcements=[])

@app.route('/admin/announcement/<int:announcement_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_announcement(announcement_id):
    result = api_request('DELETE', f'/api/admin/announcements/{announcement_id}')
    if result.get('success'):
        flash('Announcement deleted successfully!', 'success')
    else:
        flash(result.get('error', 'Deletion failed'), 'error')
    return redirect(url_for('admin_announcements'))

@app.route('/admin/leaves')
@login_required
@admin_required
def admin_leaves():
    params = {'status': request.args.get('status', 'PENDING')}
    result = api_request('GET', '/api/admin/leaves', params)
    if result.get('success'):
        return render_template('admin/leaves.html', **result['data'])
    return render_template('admin/leaves.html', leave_requests=[])

@app.route('/admin/leave/<int:leave_id>/approve', methods=['POST'])
@login_required
@admin_required
def approve_leave(leave_id):
    data = {'admin_comment': request.form.get('admin_comment', '')}
    result = api_request('POST', f'/api/admin/leaves/{leave_id}/approve', data)
    if result.get('success'):
        flash('Leave request approved!', 'success')
    else:
        flash(result.get('error', 'Approval failed'), 'error')
    return redirect(url_for('admin_leaves'))

@app.route('/admin/leave/<int:leave_id>/reject', methods=['POST'])
@login_required
@admin_required
def reject_leave(leave_id):
    data = {'admin_comment': request.form.get('admin_comment', '')}
    result = api_request('POST', f'/api/admin/leaves/{leave_id}/reject', data)
    if result.get('success'):
        flash('Leave request rejected.', 'info')
    else:
        flash(result.get('error', 'Rejection failed'), 'error')
    return redirect(url_for('admin_leaves'))

@app.route('/admin/certificates')
@login_required
@admin_required
def admin_certificates():
    result = api_request('GET', '/api/admin/certificates')
    if result.get('success'):
        return render_template('admin/certificates.html', **result['data'])
    return render_template('admin/certificates.html', interns=[])

@app.route('/admin/generate-certificate/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def generate_certificate(user_id):
    result = api_request('POST', f'/api/admin/certificates/generate/{user_id}')
    if result.get('success'):
        flash('Certificate generated successfully!', 'success')
    else:
        flash(result.get('error', 'Generation failed'), 'error')
    return redirect(url_for('admin_certificates'))

@app.route('/admin/certificates/generate-all', methods=['POST'])
@login_required
@admin_required
def admin_generate_all_certificates():
    result = api_request('POST', '/api/admin/certificates/generate-all')
    if result.get('success'):
        flash(result.get('message', 'Certificates generated'), 'success')
    else:
        flash(result.get('error', 'Generation failed'), 'error')
    return redirect(url_for('admin_certificates'))

@app.route('/admin/certificate/delete/<int:cert_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_certificate(cert_id):
    result = api_request('DELETE', f'/api/admin/certificates/{cert_id}')
    if result.get('success'):
        flash('Certificate revoked successfully.', 'info')
    else:
        flash(result.get('error', 'Deletion failed'), 'error')
    return redirect(url_for('admin_certificates'))

@app.route('/admin/certificate/view/<int:cert_id>')
@login_required
@admin_required
def admin_view_certificate(cert_id):
    result = api_request('GET', f'/api/admin/certificates/{cert_id}')
    if result.get('success'):
        return render_template('admin/view_certificate.html', cert=result['data'])
    flash('Certificate not found.', 'error')
    return redirect(url_for('admin_certificates'))

@app.route('/admin/messages', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_messages():
    if request.method == 'POST':
        data = {
            'recipient_id': request.form.get('recipient_id'),
            'subject': request.form.get('subject'),
            'content': request.form.get('content'),
            'is_broadcast': request.form.get('is_broadcast') == 'on'
        }
        result = api_request('POST', '/api/admin/messages', data)
        if result.get('success'):
            flash('Message sent successfully!', 'success')
        else:
            flash(result.get('error', 'Sending failed'), 'error')
        return redirect(url_for('admin_messages'))
    
    result = api_request('GET', '/api/admin/messages')
    if result.get('success'):
        return render_template('admin/messages.html', **result['data'])
    return render_template('admin/messages.html', sent_messages=[], interns=[])

@app.route('/admin/analytics')
@login_required
@admin_required
def admin_analytics():
    result = api_request('GET', '/api/admin/analytics')
    if result.get('success'):
        return render_template('admin/analytics.html', **result['data'])
    return render_template('admin/analytics.html')

# ============================================================================
# INTERN ROUTES
# ============================================================================

@app.route('/intern/dashboard')
@login_required
@approved_required
def intern_dashboard():
    result = api_request('GET', '/api/intern/dashboard')
    if result.get('success'):
        return render_template('intern/dashboard.html', **result['data'])
    return render_template('intern/dashboard.html')

@app.route('/intern/profile', methods=['GET', 'POST'])
@login_required
@approved_required
def intern_profile():
    if request.method == 'POST':
        if request.form.get('update_profile'):
            data = {
                'phone': request.form.get('phone'),
                'address': request.form.get('address'),
                'emergency_contact': request.form.get('emergency_contact')
            }
            
            # Handle photo upload
            if 'cropped_image' in request.files:
                photo_file = request.files['cropped_image']
                if photo_file and photo_file.filename:
                    files = {'photo': photo_file}
                    result = api_request('POST', '/api/intern/profile/update', data, files=files)
                else:
                    result = api_request('POST', '/api/intern/profile/update', data)
            else:
                result = api_request('POST', '/api/intern/profile/update', data)
            
            if result.get('success'):
                flash('Profile updated successfully! ✅', 'success')
                return jsonify({'success': True}) if 'X-Requested-With' in request.headers else redirect(url_for('intern_profile'))
            else:
                flash(result.get('error', 'Update failed'), 'error')
                return jsonify({'success': False}) if 'X-Requested-With' in request.headers else redirect(url_for('intern_profile'))
        
        elif request.form.get('change_password'):
            data = {
                'current_password': request.form.get('current_password'),
                'new_password': request.form.get('new_password'),
                'confirm_password': request.form.get('confirm_password')
            }
            result = api_request('POST', '/api/intern/profile/change-password', data)
            if result.get('success'):
                flash('Password changed successfully! 🔐', 'success')
            else:
                flash(result.get('error', 'Password change failed'), 'error')
            return redirect(url_for('intern_profile'))
    
    result = api_request('GET', '/api/intern/profile')
    if result.get('success'):
        return render_template('intern/profile.html', **result['data'])
    return render_template('intern/profile.html')

@app.route('/intern/attendance', methods=['GET', 'POST'])
@login_required
@approved_required
def intern_attendance():
    result = api_request('GET', '/api/intern/attendance')
    if result.get('success'):
        return render_template('intern/attendance.html', **result['data'])
    return render_template('intern/attendance.html')

@app.route('/intern/attendance/mark', methods=['POST'])
@login_required
@approved_required
def intern_mark_attendance():
    data = {'location': request.form.get('location', '')}
    result = api_request('POST', '/api/intern/attendance/mark', data)
    return jsonify(result)

@app.route('/intern/attendance/checkout', methods=['POST'])
@login_required
@approved_required
def intern_checkout():
    result = api_request('POST', '/api/intern/attendance/checkout')
    return jsonify(result)

@app.route('/intern/tasks')
@login_required
@approved_required
def intern_tasks():
    params = {'status': request.args.get('status', 'all')}
    result = api_request('GET', '/api/intern/tasks', params)
    if result.get('success'):
        return render_template('intern/tasks.html', **result['data'])
    return render_template('intern/tasks.html', tasks=[])

@app.route('/intern/submit', methods=['GET', 'POST'])
@login_required
@approved_required
def intern_submit():
    if request.method == 'POST':
        data = {
            'task_id': request.form.get('task_id'),
            'content': request.form.get('content'),
            'file_data': request.form.get('file_data'),
            'file_type': request.form.get('file_type', 'other')
        }
        result = api_request('POST', '/api/intern/submissions/submit', data)
        if result.get('success'):
            flash('Submission sent successfully! Awaiting admin review.', 'success')
        else:
            flash(result.get('error', 'Submission failed'), 'error')
        return redirect(url_for('intern_submissions'))
    
    result = api_request('GET', '/api/intern/tasks/available')
    if result.get('success'):
        return render_template('intern/submit_work.html', tasks=result['data'])
    return render_template('intern/submit_work.html', tasks=[])

@app.route('/intern/submissions')
@login_required
@approved_required
def intern_submissions():
    params = {'status': request.args.get('status', 'all')}
    result = api_request('GET', '/api/intern/submissions', params)
    if result.get('success'):
        return render_template('intern/submissions.html', **result['data'])
    return render_template('intern/submissions.html', submissions=[])

@app.route('/intern/leave', methods=['GET', 'POST'])
@login_required
@approved_required
def intern_leave():
    if request.method == 'POST':
        data = {
            'leave_type': request.form.get('leave_type'),
            'start_date': request.form.get('start_date'),
            'end_date': request.form.get('end_date'),
            'reason': request.form.get('reason')
        }
        result = api_request('POST', '/api/intern/leave/request', data)
        if result.get('success'):
            flash('Leave request submitted successfully!', 'success')
        else:
            flash(result.get('error', 'Submission failed'), 'error')
        return redirect(url_for('intern_leave'))
    
    result = api_request('GET', '/api/intern/leave')
    if result.get('success'):
        return render_template('intern/leave.html', leave_requests=result['data'])
    return render_template('intern/leave.html', leave_requests=[])

@app.route('/intern/announcements')
@login_required
@approved_required
def intern_announcements():
    result = api_request('GET', '/api/intern/announcements')
    if result.get('success'):
        return render_template('intern/announcements.html', announcements=result['data'])
    return render_template('intern/announcements.html', announcements=[])

@app.route('/intern/messages')
@login_required
@approved_required
def intern_messages():
    result = api_request('GET', '/api/intern/messages')
    if result.get('success'):
        return render_template('intern/messages.html', messages=result['data'])
    return render_template('intern/messages.html', messages=[])

@app.route('/intern/message/<int:message_id>/read', methods=['POST'])
@login_required
@approved_required
def mark_message_read(message_id):
    result = api_request('POST', f'/api/intern/messages/{message_id}/read')
    return jsonify(result)

@app.route('/intern/goals', methods=['GET', 'POST'])
@login_required
@approved_required
def intern_goals():
    if request.method == 'POST':
        data = {
            'title': request.form.get('title'),
            'description': request.form.get('description'),
            'target_date': request.form.get('target_date')
        }
        result = api_request('POST', '/api/intern/goals', data)
        if result.get('success'):
            flash('Goal created successfully!', 'success')
        else:
            flash(result.get('error', 'Creation failed'), 'error')
        return redirect(url_for('intern_goals'))
    
    result = api_request('GET', '/api/intern/goals')
    if result.get('success'):
        return render_template('intern/goals.html', goals=result['data'])
    return render_template('intern/goals.html', goals=[])

@app.route('/intern/goal/<int:goal_id>/update', methods=['POST'])
@login_required
@approved_required
def update_goal(goal_id):
    data = {
        'progress': request.form.get('progress'),
        'status': request.form.get('status')
    }
    result = api_request('PUT', f'/api/intern/goals/{goal_id}', data)
    if result.get('success'):
        flash('Goal updated!', 'success')
    else:
        flash(result.get('error', 'Update failed'), 'error')
    return redirect(url_for('intern_goals'))

@app.route('/intern/skills', methods=['GET', 'POST'])
@login_required
@approved_required
def intern_skills():
    if request.method == 'POST':
        data = {
            'skill_name': request.form.get('skill_name'),
            'proficiency_level': request.form.get('proficiency_level')
        }
        result = api_request('POST', '/api/intern/skills', data)
        if result.get('success'):
            flash('Skill added successfully!', 'success')
        else:
            flash(result.get('error', 'Addition failed'), 'error')
        return redirect(url_for('intern_skills'))
    
    result = api_request('GET', '/api/intern/skills')
    if result.get('success'):
        return render_template('intern/skills.html', skills=result['data'])
    return render_template('intern/skills.html', skills=[])

@app.route('/intern/documents', methods=['GET', 'POST'])
@login_required
@approved_required
def intern_documents():
    if request.method == 'POST':
        data = {
            'document_type': request.form.get('document_type'),
            'document_name': request.form.get('document_name'),
            'file_data': request.form.get('file_data')
        }
        result = api_request('POST', '/api/intern/documents', data)
        if result.get('success'):
            flash('Document uploaded successfully! Awaiting verification.', 'success')
        else:
            flash(result.get('error', 'Upload failed'), 'error')
        return redirect(url_for('intern_documents'))
    
    result = api_request('GET', '/api/intern/documents')
    if result.get('success'):
        return render_template('intern/documents.html', documents=result['data'])
    return render_template('intern/documents.html', documents=[])

@app.route('/intern/notifications')
@login_required
@approved_required
def intern_notifications():
    result = api_request('GET', '/api/intern/notifications')
    if result.get('success'):
        return render_template('intern/notifications.html', notifications=result['data'])
    return render_template('intern/notifications.html', notifications=[])

@app.route('/intern/certificates')
@login_required
@approved_required
def intern_certificates():
    result = api_request('GET', '/api/intern/certificates')
    if result.get('success'):
        return render_template('intern/certificates.html', certificates=result['data'])
    return render_template('intern/certificates.html', certificates=[])

@app.route('/intern/certificate/view/<int:cert_id>')
@login_required
@approved_required
def intern_view_certificate(cert_id):
    result = api_request('GET', f'/api/intern/certificates/{cert_id}')
    if result.get('success'):
        return render_template('intern/view_certificate.html', cert=result['data'])
    flash('Certificate not found.', 'error')
    return redirect(url_for('intern_certificates'))

# ============================================================================
# PUBLIC CERTIFICATE VERIFICATION
# ============================================================================

@app.route('/verify/certificate/', defaults={'code': None})
@app.route('/verify/certificate/<code>')
def verify_certificate(code):
    if not code:
        return render_template('public/verify_certificate_scanner.html')
    
    result = api_request('GET', f'/api/certificates/verify/{code}')
    if result.get('success'):
        return render_template('public/verify_certificate.html', 
                             cert=result['data'], 
                             verified=True)
    else:
        return render_template('public/verify_certificate.html', 
                             verified=False, 
                             error=result.get('error', 'Invalid verification code'))

@app.route('/certificate/<code>')
def view_certificate(code):
    result = api_request('GET', f'/api/certificates/view/{code}')
    if result.get('success'):
        return render_template('intern/view_certificate.html', cert=result['data'])
    return "Invalid Certificate Link", 404

# ============================================================================
# API ENDPOINTS (for AJAX)
# ============================================================================

@app.route('/api/notifications/unread')
@login_required
def api_unread_notifications():
    result = api_request('GET', '/api/notifications/unread')
    if result.get('success'):
        return jsonify({'count': result.get('count', 0)})
    return jsonify({'count': 0})

@app.route('/debug-files')
def debug_files():
    """Temporarily check what files exist on Vercel"""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    files = []
    for root, dirs, filenames in os.walk(current_dir):
        for filename in filenames:
            files.append(os.path.join(root, filename))
    return '<br>'.join(files)
# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(e):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('errors/500.html'), 500

# ============================================================================
# CONTEXT PROCESSOR
# ============================================================================

@app.context_processor
def inject_globals():
    unread_count = 0
    if current_user.is_authenticated:
        result = api_request('GET', '/api/notifications/unread')
        if result.get('success'):
            unread_count = result.get('count', 0)
    
    return {
        'now': datetime.now(),
        'app_name': 'Shramic ERP',
        'unread_notifications': unread_count
    }

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    print("🚀 SHRAMIC ERP FRONTEND - STARTED (Vercel)")
    app.run(debug=False, host='0.0.0.0', port=5000)