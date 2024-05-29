# For authentication code
from flask import Blueprint,render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        email    = request.form.get('email')
        password = request.form.get('passwordl1')
        user = User.query.filter_by(email=email).first()
        if user:
            print(password)
            if check_password_hash(user.password, password):
                flash("Logged in", category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash("Incorrect password", category='error')
        else:
            flash("Please check username or password 1", category='error')
    return render_template("login.html", user=current_user)


@auth.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == "POST":
        email     = request.form.get('email')
        firstName = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        if (User.query.filter_by(email=email).first()):
            flash("This user already exists", category='error')
        if len(email) < 4:
            flash("Email should be greater than 4 characters", category='error')
        elif len(firstName) < 2:
            flash("Firstname should be greater than 2 characters", category='error')
        elif password1 != password2:
            flash("Passwords dont\'t match", category='error')
        else:
            new_user = User(email=email, firstName=firstName, password=generate_password_hash(password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            flash("User registered!", category='success')
            return redirect(url_for("views.home"))

    return render_template("signup.html", user=current_user)
