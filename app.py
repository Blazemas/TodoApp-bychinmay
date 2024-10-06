from flask import Flask, render_template, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
# from flask_migrate import Migrate

app = Flask(__name__)

# Configuring the SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///todo.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'  # Required for Flask-Login

# Initializing the database
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# Assuming 'db' is already initialized as SQLAlchemy instance
# migrate = Migrate(app, db)

# User model for authentication
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)


# Todo model associated with the user
class Todo(db.Model):
    srno = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(400), nullable=False)
    desc = db.Column(db.String(400), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) # Link todo to a user

    def __repr__(self) -> str:
        return f"{self.srno} and {self.title}"


# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Routes
@app.route('/', methods=['GET', 'POST'])
@login_required
def home():
    if request.method == 'POST':
        todo_title = request.form['title']
        todo_desc = request.form['desc']
        todo = Todo(title=todo_title, desc=todo_desc, user_id=current_user.id) # Associate with logged-in user
        db.session.add(todo)
        db.session.commit()

    alltodo = Todo.query.filter_by(user_id=current_user.id).all()  # Filter todos by user
    return render_template("index2.html", alltodo=alltodo)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect('/')
        else:
            return 'Invalid credentials'
        
    return render_template("login.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/login')

    return render_template("register.html")


@app.route('/update/<srno>', methods=['GET', 'POST'])
@login_required
def update(srno):
    todo1 = Todo.query.filter_by(srno=srno, user_id=current_user.id).first()

    if not todo1:
        return "You do not have permission to update this item."

    if request.method == 'POST':
        todo_title = request.form['title']
        todo_desc = request.form['desc']
        todo1.title = todo_title
        todo1.desc = todo_desc
        db.session.commit()
        return redirect("/")

    return render_template("update.html", todo1=todo1)


@app.route('/delete/<srno>')
@login_required
def delete(srno):
    todo1 = Todo.query.filter_by(srno=srno, user_id=current_user.id).first()

    if not todo1:
        return "You do not have permission to delete this item."

    db.session.delete(todo1)
    db.session.commit()
    return redirect("/")


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')

@app.route('/contact')
@login_required
def contact():
    return render_template("contact.html")

@app.route('/about')
@login_required
def about():
    return render_template("about.html")


# @app.route('/viewall')
# def viewall():
#     return render_template("viewall.html")

# Function to create the database within the app context
def create_db():
    with app.app_context():
        db.create_all()
        print("Database created successfully.")


if __name__ == "__main__":
    create_db()
    app.run(debug=False, port=8000)
