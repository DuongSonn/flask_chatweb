from flask import Flask,render_template,request,redirect,session,jsonify,url_for
from flask_sqlalchemy import SQLAlchemy 
from flask_bcrypt import Bcrypt
from flask_login import login_user,LoginManager,UserMixin,current_user,login_required
from flask_session import Session
from flask_socketio import SocketIO,send,emit,join_room,leave_room
from flask_marshmallow import Marshmallow
from datetime import datetime
from sqlalchemy import text
from werkzeug.utils import secure_filename
import redis
import re
import json
import os

userConnect = []
userRoom = []

app = Flask(__name__)
# flask-bcrypt
bcrypt = Bcrypt(app)

# flask-session
sess = Session()

# flask-login
login_manager = LoginManager()
login_manager.init_app(app)

#flask-sqlalchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:123abnkakashi@localhost:1998/flask_chatweb'
db = SQLAlchemy(app)
ma = Marshmallow(app)
#flask-socketio
app.config['SECRET_KEY'] = 'secret key'
socketio = SocketIO(app)

#upload file
dir_path = os.path.dirname(os.path.realpath(__file__))
UPLOAD_FOLDER = dir_path + '/user_image'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

#model User
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key =True)
    email = db.Column(db.String(200), nullable = False, unique=True)
    phone = db.Column(db.String(200), nullable = False, unique=True)
    username = db.Column(db.String(200), nullable = False, unique=True)
    password = db.Column(db.String(200), nullable = False)
    status = db.Column(db.Boolean, default=False, nullable=False)
    image = db.Column(db.String(200), default='user.jpg')

    def __repr__(self):
        return '<Task %r>' %self.id

#model Message
class Message(db.Model):
    id = db.Column(db.Integer, primary_key =True)
    user_1 = db.Column(db.Integer, db.ForeignKey('user.id'), nullable = False)
    user_2 = db.Column(db.Integer, db.ForeignKey('user.id'), nullable = False)
    content = db.Column(db.String(500), nullable = False)
    datetime = db.Column(db.DateTime, nullable = False)

    def __repr__(self):
        return '<Task %r>' %self.id

#mashmallow for model
class UserSchema(ma.ModelSchema):
    class Meta:
        model = User

class MesssageSchema(ma.ModelSchema):
    class Meta:
        model = Message
        include_fk = True

@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(id=user_id).first()

def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# login route
@app.route('/', methods = ['POST','GET'])
def login_index():
    emailErr = ''
    passErr = ''
    if (request.method == 'POST'):
        email = request.form['email']
        password = request.form['password']
        if (email == ''):
            emailErr = '*Email cant be blank'
        elif(not re.search('^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$',email)):
            emailErr = '*Incorrect email format'
        if (password == ''):
            passErr == '*Password cant be bank'
        else :
            user = User.query.filter_by(email=email).first()
            if user is None:
                emailErr = "*Email doesnt exist" 
            else:
                if (not bcrypt.check_password_hash(user.password, password)):
                    passErr = '*Incorrect password'
        if (passErr == '' and emailErr == ''):
            login_user(user, remember=True)
            if (user.is_authenticated):
                return redirect('/index')
            else:
                return "Error"
        else:
            return render_template('login.html', emailErr = emailErr, passErr = passErr, command='Error')
    else:
        return render_template('login.html')

# sign up route
@app.route('/signup', methods = ['POST','GET'])
def signup_index():
    emailErr = ''
    passErr = ''
    usernameErr = ''
    phoneErr = ''
    confErr = ''
    if (request.method == 'POST'):
        email = request.form['email']
        password = request.form['password']
        username = request.form['username']
        phone = request.form['phone']
        confirmpassword = request.form['confirmpassword']
        if (email == ''):
            emailErr = '*Email cant be blank'
        elif (not re.search('^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$',email)):
            emailErr = '*Incorrect email format'
        elif (emailErr == ''):
            user = User.query.filter_by(email=email).first()
            if (user is not None):
                emailErr = '*Email already exists'
        if (password == ''):
            passErr == '*Password cant be bank'
        if (username == ''):
            usernameErr = '*Username cant be blank'
        elif (usernameErr == ''):
            user = User.query.filter_by(username=username).first()
            if (user is not None):
                usernameErr = '*Username already exists'
        if (phone == ''):
            phoneErr = '*Phone cant be blank'
        elif (phoneErr == ''):
            user = User.query.filter_by(phone=phone).first()
            if (user is not None):
                phoneErr = '*Phone number already exists'
        if (confirmpassword == ''):
            confErr = '*Confirm password cant be blank'
        elif (confirmpassword != password):
            confErr = '*Password is different'
        if(emailErr == '' and usernameErr == '' and phoneErr == '' and passErr == '' and confErr == ''):
            password = bcrypt.generate_password_hash(password)
            user = User(email=email ,phone=phone ,username=username ,password=password )
            db.session.add(user)
            db.session.commit()
            return redirect('/')
        else:
            return render_template('signup.html', emailErr = emailErr, phoneErr = phoneErr, usernameErr = usernameErr, passErr = passErr, confErr = confErr, command='Error')
    else:
        return render_template('signup.html')

# index route
@app.route('/index', methods = ['POST','GET'])
@login_required
def index():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            print(filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return redirect(url_for('index',filename=filename)) 
    else :
        users = User.query.filter(User.email != current_user.email).all()
        return render_template("index.html", users = users, current_user = current_user)
    
@socketio.on('connect', namespace = '/index')
def on_connect():
    if current_user.is_authenticated :
        print(request.sid)
        # user = User.query.filter_by(id=current_user.id).first()
        # user.status = True
        # db.session.commit()
        # users = User.query.all()
        # user_schema = UserSchema(many=True)
        # json = user_schema.dump(users)
        if (current_user.id not in userConnect):
            userConnect.append(current_user.id)
            userRoom.append(request.sid)
        else :
            for i,user in enumerate(userConnect):
                if (current_user.id == user):
                    userRoom.remove(userRoom[i])
                    userConnect.remove(current_user.id)
                    userConnect.append(current_user.id)
                    userRoom.append(request.sid)
        msg = {'connect_id': userConnect}
        emit('my response connect', msg, broadcast = True)

@socketio.on('disconnect', namespace = '/index')
def on_disconnect():
    print('Client disconnected ' + str(current_user.id))
    if (current_user.id in userConnect):
        for i,user in enumerate(userConnect):
            if (current_user.id == user):
                userRoom.remove(userRoom[i])
        userConnect.remove(current_user.id)
    msg = {'disconnect_id': current_user.id}
    emit('my response disconnect', msg, broadcast = True)

@socketio.on('my event chat', namespace = '/index')
def on_message(msg):
    if current_user.is_authenticated :
        message = Message(user_1 = int(msg['receiver']), user_2 = int(msg['sender']), content = msg['message'], datetime= msg['time'])
        db.session.add(message)
        db.session.commit()
        for i,user in enumerate(userConnect):
            if (int(msg['receiver']) == user):
                emit('my response chat', msg, room = userRoom[i])

@socketio.on('my event chat history', namespace = '/index')
def on_message(msg):
    if current_user.is_authenticated :
        sql = text('select * from message WHERE ( user_1 = :x AND user_2 = :y ) OR ( user_1 = :y AND user_2 = :x ) AND content IS NOT NULL ORDER BY datetime LIMIT 10')
        msgs = db.engine.execute(sql , x=int(msg['receiver']), y=msg['sender']).fetchall()
        msg_schema = MesssageSchema(many=True)
        json = msg_schema.dump(msgs)
        for i,user in enumerate(userConnect):
            if (msg['sender'] == user):
                emit('my response chat history', json, room = userRoom[i])


#run
if __name__ == "__main__":
    app.secret_key = 'super secret key'
    app.config['SESSION_TYPE'] = 'redis'
    sess.init_app(app)
    app.run(debug=True)