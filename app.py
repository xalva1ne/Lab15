import os
from flask import Flask, render_template, request, redirect, url_for, session, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = '123'

app.template_folder = os.path.abspath('templates')

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    admin = db.Column(db.Boolean, default=False)


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        user = None
        if 'user_id' in session:
            user_id = session['user_id']
            user = User.query.get(user_id)

        if user:
            return func(*args, **kwargs)

        return redirect(url_for('login'))

    return wrapper

@app.route('/')
def home():
    if 'user_id' in session:
        current_user_id = session['user_id']
        current_user = User.query.get(current_user_id)
        if current_user.admin:
            users = User.query.all()
            return render_template('index.html', users=users)
        else:
            return render_template('index.html')
    else:
        return render_template('index.html')

@app.route('/auth/', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('user'))    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='sha256')

        new_user = User(username=username, password_hash=hashed_password)
        if username == 'root' and password == 'admin':
            new_user.admin = True
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('auth.html')

@app.route('/login/', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('user'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            return redirect(url_for('user'))
        else:
            return render_template('auth.html', error='Invalid credentials')

    return render_template('login.html')


@app.route('/user/')
@login_required
def user():
    user_id = session['user_id']
    user = User.query.get(user_id)
    return render_template('user.html', user=user)

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return redirect(url_for('home'))

@app.route('/user_list', methods=['GET'])
@login_required
def user_list():
        current_user_id = session['user_id']
        current_user = User.query.get(current_user_id)

        if current_user.admin:
            users = User.query.all()
            return render_template('user_list.html', users=users)
        else:
            abort(403)

@app.route('/delete_user/<int:user_id>', methods=['GET'])
@login_required
def delete_user(user_id):

        current_user_id = session['user_id']
        current_user = User.query.get(current_user_id)

        if current_user.admin:
            user_to_delete = User.query.get(user_id)
            db.session.delete(user_to_delete)
            db.session.commit()
            return redirect(url_for('user_list'))
        else:
            abort(403)

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
