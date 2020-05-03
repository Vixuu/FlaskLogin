from flask import Flask, render_template, redirect, url_for, flash, get_flashed_messages
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from forms import RegisterForm, LoginForm

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dae87ad03483cbc81be87a131bd22c6253ed15bd668f3140b43635e2x'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///base.db'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


#-Database user class-#
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    isApproved = db.Column(db.Boolean, default=False, nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


#---ROUTES---##---ROUTES---##---ROUTES---#
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST']) 
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data) and user.isApproved:
                login_user(user, remember=form.remember.data)
                flash("Successfully logged in" , "success")
                return redirect(url_for('dashboard'))
            elif user.isApproved == False:
                flash("You haven't been approved yet", 'info')
            else:
                flash("Invalid username or password", "danger")
        else:
            flash("User does not exist" , "warning")
    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_pwd = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_pwd)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('index'))

    return render_template('signup.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)


