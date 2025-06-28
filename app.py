from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///voting.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)

    def get_id(self):
        return str(self.user_id)


class Election(db.Model):
    election_id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(50), default='upcoming')


class Candidate(db.Model):
    candidate_id = db.Column(db.Integer, primary_key=True)
    election_id = db.Column(db.Integer, db.ForeignKey('election.election_id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    party = db.Column(db.String(100))
    position = db.Column(db.String(50))


class Vote(db.Model):
    vote_id = db.Column(db.Integer, primary_key=True)
    voter_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    election_id = db.Column(db.Integer, db.ForeignKey('election.election_id'), nullable=False)
    candidate_id = db.Column(db.Integer, db.ForeignKey('candidate.candidate_id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('voter_id', 'election_id', name='unique_vote'),)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
@login_required
def dashboard():
    elections = Election.query.all()
    return render_template('dashboard.html', elections=elections)


@app.route('/election/<int:election_id>')
@login_required
def election_detail(election_id):
    election = Election.query.get_or_404(election_id)
    candidates = Candidate.query.filter_by(election_id=election_id).all()
    return render_template('election.html', election=election, candidates=candidates)


@app.route('/vote/<int:election_id>', methods=['GET', 'POST'])
@login_required
def vote(election_id):
    candidates = Candidate.query.filter_by(election_id=election_id).all()
    if request.method == 'POST':
        candidate_id = request.form.get('candidate_id')
        if not candidate_id:
            flash('Please select a candidate.', 'danger')
            return redirect(url_for('vote', election_id=election_id))

        existing_vote = Vote.query.filter_by(voter_id=current_user.user_id, election_id=election_id).first()
        if existing_vote:
            flash('You have already voted in this election!', 'danger')
            return redirect(url_for('dashboard'))

        vote = Vote(voter_id=current_user.user_id, election_id=election_id, candidate_id=int(candidate_id))
        db.session.add(vote)
        db.session.commit()
        flash('Vote cast successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('vote.html', candidates=candidates, election_id=election_id)


@app.route('/results/<int:election_id>')
@login_required
def results(election_id):
    election = Election.query.get_or_404(election_id)
    candidates = Candidate.query.filter_by(election_id=election_id).all()
    labels = []
    data = []

    for candidate in candidates:
        vote_count = Vote.query.filter_by(candidate_id=candidate.candidate_id).count()
        labels.append(candidate.name)
        data.append(vote_count)

    return render_template('results.html', election=election, labels=labels, data=data)


@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_panel():
    if current_user.role != 'admin':
        flash('Access Denied!', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        start_time = request.form.get('start_time')
        end_time = request.form.get('end_time')

        if not (title and start_time and end_time):
            flash('All fields except description are required.', 'danger')
            return redirect(url_for('admin_panel'))

        try:
            start_time_obj = datetime.strptime(start_time, '%Y-%m-%dT%H:%M')
            end_time_obj = datetime.strptime(end_time, '%Y-%m-%dT%H:%M')
        except ValueError:
            flash('Invalid date format.', 'danger')
            return redirect(url_for('admin_panel'))

        election = Election(
            title=title,
            description=description,
            start_time=start_time_obj,
            end_time=end_time_obj
        )
        db.session.add(election)
        db.session.commit()
        flash('Election created successfully!', 'success')
        return redirect(url_for('admin_panel'))

    elections = Election.query.all()
    return render_template('admin_panel.html', elections=elections)


@app.route('/add_candidate/<int:election_id>', methods=['GET', 'POST'])
@login_required
def add_candidate(election_id):
    if current_user.role != 'admin':
        flash('Access denied!', 'danger')
        return redirect(url_for('dashboard'))

    election = Election.query.get_or_404(election_id)

    if request.method == 'POST':
        name = request.form.get('name')
        party = request.form.get('party')
        position = request.form.get('position')

        if not name:
            flash('Candidate name is required.', 'danger')
            return redirect(url_for('add_candidate', election_id=election_id))

        candidate = Candidate(
            election_id=election_id,
            name=name,
            party=party,
            position=position
        )
        db.session.add(candidate)
        db.session.commit()
        flash('Candidate added successfully!', 'success')
        return redirect(url_for('election_detail', election_id=election_id))

    return render_template('add_candidate.html', election=election)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'danger')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        password = generate_password_hash(request.form.get('password'))

        if User.query.filter_by(email=email).first():
            flash('Email already exists.', 'danger')
            return redirect(url_for('register'))

        user = User(full_name=full_name, email=email, password=password, role='voter')
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        admin_email = 'admin@example.com'
        admin = User.query.filter_by(email=admin_email).first()
        if not admin:
            admin = User(
                full_name="Admin User",
                email=admin_email,
                password=generate_password_hash('admin12345'),
                role="admin"
            )
            db.session.add(admin)
            print('✅ Admin user created: admin@example.com / admin123')

        dummy_voters = [
            {"name": "John Doe", "email": "john@example.com", "password": "john123"},
            {"name": "Jane Smith", "email": "jane@example.com", "password": "jane123"},
            {"name": "Michael Brown", "email": "michael@example.com", "password": "michael123"},
        ]

        for voter in dummy_voters:
            existing = User.query.filter_by(email=voter['email']).first()
            if not existing:
                new_voter = User(
                    full_name=voter['name'],
                    email=voter['email'],
                    password=generate_password_hash(voter['password']),
                    role="voter"
                )
                db.session.add(new_voter)
                print(f"✅ Voter created: {voter['email']} / {voter['password']}")

        db.session.commit()

    app.run(debug=True)
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
