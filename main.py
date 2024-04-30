from flask import Flask, flash, render_template, request,redirect, session,url_for
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from flask_bcrypt import Bcrypt
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
import logging
from sqlalchemy.sql import func
logging.basicConfig(level=logging.INFO)
app=Flask(__name__)
app.config["SECRET_KEY"]='65b0b774279de460f1cc5c92'
app.config['SQLALCHEMY_DATABASE_URI']="sqlite:///ums.sqlite"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
app.config["SESSION_PERMANENT"]=False
app.config["SESSION_TYPE"]='filesystem'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
db=SQLAlchemy(app)
bcrypt=Bcrypt(app)
Session(app)

# User Class
class User(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    fname=db.Column(db.String(255), nullable=False)
    lname=db.Column(db.String(255), nullable=False)
    email=db.Column(db.String(255), nullable=False)
    username=db.Column(db.String(255), nullable=False)
    password=db.Column(db.String(255), nullable=False)
    status=db.Column(db.Integer,default=0, nullable=False)
    
    parcels = db.relationship('Parcel', backref='user', lazy='dynamic')

    def __repr__(self):
        return f'User("{self.id}","{self.fname}","{self.lname}","{self.email}","{self.username}","{self.status}")'

#parcel class
from sqlalchemy.ext.hybrid import hybrid_property

class Parcel(db.Model):
    __tablename__ = 'parcels'

    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(255), nullable=True)
    _delivery_type = db.Column('delivery_type', db.String(50), nullable=False, default='normal')
    sender_address = db.Column(db.String(255), nullable=False)
    receiver_address = db.Column(db.String(255), nullable=False)
    _weight = db.Column('weight', db.Float, nullable=False)
    total_due = db.Column(db.Float, default=0.0, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(50), default='pending')
    delivery_requested = db.Column(db.String(50), default='pending')
    admin_id = db.Column(db.Integer, db.ForeignKey('admins.id'), nullable=True)
    

    def __repr__(self):
        return f'<Parcel {self.id} - {self.description}>'

    @hybrid_property
    def delivery_type(self):
        return self._delivery_type

    @delivery_type.setter
    def delivery_type(self, value):
        self._delivery_type = value
        self.calculate_total_due()

    @hybrid_property
    def weight(self):
        return self._weight

    @weight.setter
    def weight(self, value):
        self._weight = value
        self.calculate_total_due()

    def calculate_total_due(self):
        rate = 20.0 if self.delivery_type == 'fast' else 15.0
        self.total_due = rate * self.weight if self.weight else 0


class DeliveryBoy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    hashed_password = db.Column(db.String(128), nullable=False)
    active = db.Column(db.Boolean, default=True, nullable=False)

    def set_password(self, password):
        self.hashed_password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.hashed_password, password)

    def __repr__(self):
        return f'<DeliveryBoy {self.username}>'

class DeliveryUpdate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    parcel_id = db.Column(db.Integer, db.ForeignKey('parcels.id'), nullable=False)
    status = db.Column(db.String(100), nullable=False)  # e.g., received, out for delivery, delivered
    update_time = db.Column(db.DateTime, default=func.now())
    notes = db.Column(db.Text)

class Admin(db.Model):
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    hashed_password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(50), default='admin')
    parcels = db.relationship('Parcel', backref='admin', lazy='dynamic')
    def set_password(self, password):
        self.hashed_password = generate_password_hash(password)

    def set_password(self, password):
        self.hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')


    def __repr__(self):
        return f'<Admin {self.username}, role={self.role}>'

    # Relationship to the Parcel model
    parcel = db.relationship('Parcel', backref=db.backref('updates', lazy=True))


    
class Manager(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    hashed_password = db.Column(db.String(200), nullable=False)
    is_approved = db.Column(db.Boolean, default=False, nullable=False)

    def __repr__(self):
        return f'<Manager {self.username}>'

class Employee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    hashed_password = db.Column(db.String(128), nullable=False)
    status = db.Column(db.Boolean, default=False, nullable=False) 
    delivery_status= db.Column(db.String(50), default='pending')

    def set_password(self, password):
        self.hashed_password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.hashed_password, password)

    def __repr__(self):
        return '<Employee {}>'.format(self.username)

#admmin register
@app.route('/admin/register', methods=['GET', 'POST'])
def register_admin():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role', 'admin')

        if not username or not password:
            flash('Username and password are required.', 'error')
            return redirect("/admin/register")

        existing_admin = Admin.query.filter_by(username=username).first()
        if existing_admin:
            flash('Username already exists.', 'error')
            return redirect("/admin/register")

        new_admin = Admin(username=username, role=role)
        new_admin.set_password(password)
        db.session.add(new_admin)
        db.session.commit()
        flash('Admin registered successfully!', 'success')
        return redirect("/admin/login")
    return render_template('/admin/registration.html')





@app.route('/')
def index():
    return render_template('index.html',title="")
# admin loign
@app.route('/admin/login', methods=['GET', 'POST'])

def adminlogin():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Please fill all the fields', 'danger')
            return redirect('/admin/login')

        admin = Admin.query.filter_by(username=username).first()
        if admin and bcrypt.check_password_hash(admin.hashed_password, password):
            session['admin_id'] = admin.id
            session['admin_name'] = admin.username
            flash('Login Successfully', 'success')
            return redirect('/admin/dashboard')
        else:
            flash('Invalid Username and Password', 'danger')
            return redirect('/admin/login')
    else:
        return render_template('admin/index.html', title="Admin Login")

# admin Dashboard
@app.route('/admin/dashboard')
def adminDashboard():
    if not session.get('admin_id'):
        return redirect('/admin/')
    totalUser=User.query.count()
    totalApprove=User.query.filter_by(status=1).count()
    NotTotalApprove=User.query.filter_by(status=0).count()
    return render_template('admin/dashboard.html',title="Admin Dashboard",totalUser=totalUser,totalApprove=totalApprove,NotTotalApprove=NotTotalApprove)

# admin get all user 
@app.route('/admin/get-all-user', methods=["POST","GET"])
def adminGetAllUser():
    if not session.get('admin_id'):
        return redirect('/admin/')
    if request.method== "POST":
        search=request.form.get('search')
        users=User.query.filter(User.username.like('%'+search+'%')).all()
        return render_template('admin/all-user.html',title='Approve User',users=users)
    else:
        users=User.query.all()
        return render_template('admin/all-user.html',title='Approve User',users=users)
#admin aprove
@app.route('/admin/approve-user/<int:id>')
def adminApprove(id):
    if not session.get('admin_id'):
        return redirect('/admin/')
    User().query.filter_by(id=id).update(dict(status=1))
    db.session.commit()
    flash('Approve Successfully','success')
    return redirect('/admin/get-all-user')

# change admin password
@app.route('/admin/change-admin-password',methods=["POST","GET"])
def adminChangePassword():
    admin=Admin.query.get(1)
    if request.method == 'POST':
        username=request.form.get('username')
        password=request.form.get('password')
        if username == "" or password=="":
            flash('Please fill the field','danger')
            return redirect('/admin/change-admin-password')
        else:
            Admin().query.filter_by(username=username).update(dict(password=bcrypt.generate_password_hash(password,10)))
            db.session.commit()
            flash('Admin Password update successfully','success')
            return redirect('/admin/change-admin-password')
    else:
        return render_template('admin/admin-change-password.html',title='Admin Change Password',admin=admin)

# admin logout
@app.route('/admin/logout')
def adminLogout():
    if not session.get('admin_id'):
        return redirect('/admin/')
    if session.get('admin_id'):
        session['admin_id']=None
        session['admin_name']=None
        return redirect('/')
# -------------------------user area----------------------------



# User login
@app.route('/user/',methods=["POST","GET"])
def userIndex():
    if  session.get('user_id'):
        return redirect('/user/dashboard')
    if request.method=="POST":
        # get the name of the field
        email=request.form.get('email')
        password=request.form.get('password')
        # check user exist in this email or not
        users=User().query.filter_by(email=email).first()
        if users and bcrypt.check_password_hash(users.password,password):
            # check the admin approve your account are not
            is_approve=User.query.filter_by(id=users.id).first()
            # first return the is_approve:
            if is_approve.status == 0:
                flash('Your Account is not approved by Admin','danger')
                return redirect('/user/')
            else:
                session['user_id']=users.id
                session['username']=users.username
                flash('Login Successfully','success')
                return redirect('/user/dashboard')
        else:
            flash('Invalid Email and Password','danger')
            return redirect('/user/')
    else:
        return render_template('user/index.html',title="User Login")

# User Register
@app.route('/user/signup',methods=['POST','GET'])
def userSignup():
    if  session.get('user_id'):
        return redirect('/user/dashboard')
    if request.method=='POST':
        # get all input field name
        fname=request.form.get('fname')
        lname=request.form.get('lname')
        email=request.form.get('email')
        username=request.form.get('username')
        edu=request.form.get('edu')
        password=request.form.get('password')
        # check all the field is filled are not
        if fname =="" or lname=="" or email=="" or password=="" or username=="" or edu=="":
            flash('Please fill all the field','danger')
            return redirect('/user/signup')
        else:
            is_email=User().query.filter_by(email=email).first()
            if is_email:
                flash('Email already Exist','danger')
                return redirect('/user/signup')
            else:
                hash_password=bcrypt.generate_password_hash(password,10)
                user=User(fname=fname,lname=lname,email=email,password=hash_password,username=username)
                db.session.add(user)
                db.session.commit()
                flash('Account Create Successfully Admin Will approve your account in 10 to 30 mint ','success')
                return redirect('/user/')
    else:
        return render_template('user/signup.html',title="User Signup")


@app.route('/user/dashboard')
def user_dashboard():
    if not session.get('user_id'):
        flash("Please log in to view your dashboard.", "warning")
        return redirect(url_for('userLogin'))
    
    user = User.query.get(session['user_id'])
    if not user:
        flash("User not found.", "error")
        return redirect(url_for('userLogout'))
    else:
     return render_template('user/dashboard.html', title="User Dashboard", user=user)
# user logout
@app.route('/user/logout')
def userLogout():
    if not session.get('user_id'):
        return redirect('/user/')

    if session.get('user_id'):
        session['user_id'] = None
        session['username'] = None
        return redirect('/user/')
#user place parcel
@app.route('/user/place_parcel', methods=['GET', 'POST'])
def place_parcel():
    # Check if user is logged in
    if 'user_id' not in session:
        flash("Please log in to place a parcel.", "warning")
        return redirect(url_for('user_login'))

    # Handle form submission
    if request.method == 'POST':
        description = request.form.get('description')
        delivery_type = request.form.get('deliveryType')
        sender_address = request.form.get('senderAddress')
        receiver_address = request.form.get('receiverAddress')
        weight_str = request.form.get('weight')  # Attempt to get weight as string

        # Validate that all required fields are provided
        if not all([delivery_type, sender_address, receiver_address, weight_str]):
            flash('Please fill in all required fields.', 'error')
            # Render the form again with already input data to correct
            return render_template('user/place_parcel.html', delivery_type=delivery_type,
                                   sender_address=sender_address, receiver_address=receiver_address,
                                   description=description)

        # Convert weight to float and handle invalid data
        try:
            weight = float(weight_str)
        except ValueError:
            flash('Invalid weight. Please enter a numeric value.', 'error')
            return render_template('user/place_parcel.html', delivery_type=delivery_type,
                                   sender_address=sender_address, receiver_address=receiver_address,
                                   description=description)

        # Create and store the new parcel object
        new_parcel = Parcel(
            description=description,
            delivery_type=delivery_type,
            sender_address=sender_address,
            receiver_address=receiver_address,
            weight=weight,
            user_id=session['user_id'],
            status='pending'
        )
        db.session.add(new_parcel)
        db.session.commit()

        flash('Parcel placed successfully!', 'success')
        return redirect(url_for('user_dashboard'))

    # Render empty form if GET request
    return render_template('user/place_parcel.html')

# User Loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



#usr change password
@app.route('/user/change-password',methods=["POST","GET"])
def userChangePassword():
    if not session.get('user_id'):
        return redirect('/user/')
    if request.method == 'POST':
        email=request.form.get('email')
        password=request.form.get('password')
        if email == "" or password == "":
            flash('Please fill the field','danger')
            return redirect('/user/change-password')
        else:
            users=User.query.filter_by(email=email).first()
            if users:
               hash_password=bcrypt.generate_password_hash(password,10)
               User.query.filter_by(email=email).update(dict(password=hash_password))
               db.session.commit()
               flash('Password Change Successfully','success')
               return redirect('/user/change-password')
            else:
                flash('Invalid Email','danger')
                return redirect('/user/change-password')

    else:
        return render_template('user/change-password.html',title="Change Password")

# user update profile
@app.route('/user/update-profile', methods=["POST","GET"])
def userUpdateProfile():
    if not session.get('user_id'):
        return redirect('/user/')
    if session.get('user_id'):
        id=session.get('user_id')
    users=User.query.get(id)
    if request.method == 'POST':
        # get all input field name
        fname=request.form.get('fname')
        lname=request.form.get('lname')
        email=request.form.get('email')
        username=request.form.get('username')
        edu=request.form.get('edu')
        if fname =="" or lname=="" or email=="" or username=="" or edu=="":
            flash('Please fill all the field','danger')
            return redirect('/user/update-profile')
        else:
            session['username']=None
            User.query.filter_by(id=id).update(dict(fname=fname,lname=lname,email=email,edu=edu,username=username))
            db.session.commit()
            session['username']=username
            flash('Profile update Successfully','success')
            return redirect('/user/dashboard')
    else:
        return render_template('user/update-profile.html',title="Update Profile",users=users)
#Deliveryboy Space----------------------------------------------------------


#deliveryboy registration
@app.route('/delivery/register', methods=['GET', 'POST'])
def register_delivery_boy():
    if request.method == 'POST':
        username = request.form.get('username').strip()  # Added .strip() to remove any leading/trailing whitespace
        password = request.form.get('password')

        if not username or not password:
            flash('Both username and password are required.', 'error')
            return render_template('delivery/register.html')

        existing_user = DeliveryBoy.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists.', 'error')
            return render_template('delivery/register.html')

        new_delivery_boy = DeliveryBoy(username=username)
        new_delivery_boy.set_password(password)
        db.session.add(new_delivery_boy)
        db.session.commit()

        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login_delivery_boy'))

    return render_template('delivery/register.html')
    return render_template('delivery/register.html')
#delivery login 
@app.route('/delivery/login', methods=['GET', 'POST'])
def login_delivery_boy():
    if request.method == 'POST':
        username = request.form.get('username').strip()  # Consistency in data handling
        password = request.form.get('password')

        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('delivery/login.html')

        delivery_boy = DeliveryBoy.query.filter_by(username=username).first()
        if delivery_boy and delivery_boy.check_password(password):
            session['deliveryboy_id'] = delivery_boy.id  # Ensure consistent session key usage
            return redirect(url_for('delivery_dashboard'))
        else:
            flash('Invalid username or password.', 'error')

    return render_template('delivery/login.html')

   
#delivery dashboaed
@app.route('/delivery/dashboard')
def delivery_dashboard():
    if 'deliveryboy_id' not in session:
        flash("You must be logged in to view this page.", "warning")
        return redirect(url_for('login_delivery_boy'))

    delivery_boy_id = session.get('deliveryboy_id')
    parcels = Parcel.query.filter_by(user_id=delivery_boy_id).all()  # Check this relationship in your model
    return render_template('delivery/dashboard.html', parcels=parcels)


@app.route('/delivery/logout')
@app.route('/delivery/logout')
def delivery_logout():
    session.pop('deliveryboy_id', None)  # Correct key for session management
    flash('You have been successfully logged out.', 'success')
    return redirect(url_for('login_delivery_boy'))
#update delivery


@app.route('/delivery/update_delivery_status/<int:parcel_id>', methods=['POST'])
def update_delivery_status(parcel_id):
    if 'deliveryboy_id' not in session:
        flash("Please log in to perform this action.", "warning")
        return redirect(url_for('login_delivery_boy'))

    parcel = Parcel.query.get_or_404(parcel_id)

    # Check if the parcel's status is already 'Delivered'
    if parcel.status == "Delivered":
        flash("No further updates allowed. This delivery has already been completed.", "warning")
        return redirect(url_for('delivery_dashboard'))

    new_status = request.form.get('new_status')
    notes = request.form.get('notes', '')

    if new_status:
        update = DeliveryUpdate(parcel_id=parcel.id, status=new_status, notes=notes)
        db.session.add(update)
        parcel.status = new_status
        db.session.commit()
        flash(f"Delivery status updated successfully to {new_status}.", "success")
    else:
        flash("Invalid status update.", "danger")

    return redirect(url_for('delivery_dashboard'))




#manager space -------------------------------------------------------




#manager dashboard
@app.route('/manager/dashboard')
def manager_dashboard():
    if 'manager_id' not in session:
        flash("Please log in to access the manager dashboard", "warning")
        return redirect(url_for('manager_login'))

    # Assuming you have an Employee model with a 'status' field where status == 0 means unapproved
    unapproved_employees = Employee.query.filter_by(status=0).all()
    total_users = Employee.query.count()  # Total number of users
    pending_approvals = len(unapproved_employees)
    reports_count = 5  # Static data for example

    recent_activities = [
        {'date': '2022-10-01', 'description': 'Reviewed user submissions', 'status': 'Completed'},
        {'date': '2022-10-02', 'description': 'Updated settings', 'status': 'Completed'}
    ]

    return render_template('/manager/dashboard.html', total_users=total_users,
                           pending_approvals=pending_approvals, reports_count=reports_count,
                           recent_activities=recent_activities, unapproved_employees=unapproved_employees)


from flask import render_template, redirect, url_for, flash, session
#Manager register
@app.route('/manager/register', methods=['GET', 'POST'])
def register_manager():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        new_manager = Manager(username=username, email=email, hashed_password=hashed_password)
        db.session.add(new_manager)
        db.session.commit()
        flash('Manager registered successfully.')
        return redirect(url_for('manager_login'))
    return render_template('manager/register.html')
#Manager login

@app.route('/manager/login', methods=['GET', 'POST'])
def manager_login():
    if 'manager_id' in session:
        # If already logged in, no need to login again
        return redirect("/manager/dashboard")

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        manager = Manager.query.filter_by(username=username).first()

        if manager and check_password_hash(manager.hashed_password, password):
            session['manager_id'] = manager.id  # Log in the manager by storing their id in the session
            session['manager_username'] = manager.username  # Optionally store other details
            flash('Login successful.', 'success')
            return redirect('/manager/dashboard')
        else:
            flash('Invalid username or password.', 'error')

    return render_template('manager/login.html')


#apporove parcels

@app.route('/manager/approve_parcels')
def approve_parcels():
    if 'manager_id' not in session:
        flash("Unauthorized access. Please log in.", "danger")
        return redirect(url_for('manager_login'))

    # Assuming you have a way to fetch only pending parcels
    pending_parcels = Parcel.query.filter_by(status='pending').all()
    return render_template('manager/approve_parcels.html', parcels=pending_parcels)

#aprove employe
from flask import request

@app.route('/approve_employee/<int:employee_id>', methods=['GET', 'POST'])
def approve_employee(employee_id):
    if 'manager_id' not in session:
        flash("Please log in as a manager to approve registrations", "warning")
        return redirect(url_for('manager_login'))

    employee = Employee.query.get_or_404(employee_id)

    if request.method == 'POST':
        employee.status = True  # Set status to True to indicate approval
        db.session.commit()
        flash(f'Employee {employee.first_name} {employee.last_name} approved', 'success')
        return redirect(url_for('manager_dashboard'))
    
    # GET request: Show a confirmation page
    return render_template('employee/approve_employee.html', employee=employee)



@app.route('/manager/approve_parcel/<int:parcel_id>', methods=['GET', 'POST'])
def approve_parcel(parcel_id):
    if 'manager_id' not in session:
        flash("You must be logged in to perform this action.", "warning")
        return redirect(url_for('manager_login'))

    parcel = Parcel.query.get_or_404(parcel_id)  # This will automatically return a 404 if not found

    if request.method == 'POST':
        try:
            parcel.status = 'approved'  # Update the status
            db.session.commit()  # Commit the transaction
            flash("Parcel approved successfully.", "success")
        except Exception as e:
            db.session.rollback()  # Roll back in case of error
            flash("Error updating parcel: " + str(e), "error")  # Show error message
            return redirect(url_for('manager_dashboard'))

        return redirect(url_for('manager_dashboard'))

    # If GET request, optionally show a confirmation page or log access
    return render_template('/manager/confirm_approval.html', parcel=parcel)

@app.route('/manager/manage_users')
def manage_users():
    return render_template('manager/manage_users.html')

@app.route('/manager/reports')
def manager_reports():
    return render_template('manager/reports.html')

@app.route('/manager/settings')
def manager_settings():
    return render_template('manager/settings.html')

@app.route('/manager/help')
def help():
    return render_template('manager/help.html')
from flask import session, redirect, url_for, flash

@app.route('/manager/logout')
def manager_logout():
    # Check if the manager is logged in
    if 'manager_id' in session:
        # Clear the session
        session.pop('manager_id', None)
        flash('You have been successfully logged out.', 'success')
    else:
        flash('You are not logged in.', 'info')
    
    # Redirect to the login page or home page
    return redirect(url_for('manager_login'))
#employee space---------------------------------------------------------------------------------------
@app.route('/employee/register', methods=['GET', 'POST'])
def employee_register():
    if request.method == 'POST':
        # Getting form data with fallbacks to prevent KeyError
        first_name = request.form.get('first_name', '')
        last_name = request.form.get('last_name', '')
        email = request.form.get('email', '')
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        # Basic validation to check if all fields are filled
        if not (first_name and last_name and email and username and password):
            flash('All fields are required.')
            return redirect(url_for('employee_register'))

        # Check if email or username already exists
        if Employee.query.filter((Employee.email == email) | (Employee.username == username)).first():
            flash('Email or Username already registered.')
            return redirect(url_for('employee_register'))

        # Create new employee and set their password
        new_employee = Employee(first_name=first_name, last_name=last_name, email=email, username=username)
        new_employee.set_password(password)  # Assuming this method properly hashes the password
        db.session.add(new_employee)
        db.session.commit()
        flash('Successfully registered! Awaiting approval.')
        return redirect(url_for('employeLogin'))

    return render_template('/employee/register.html')





@app.route('/employee/login', methods=['GET', 'POST'])
def employeLogin():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Both username and password are required.', 'error')
            return redirect(url_for('employeLogin'))

        employee = Employee.query.filter_by(username=username).first()

        if employee and check_password_hash(employee.hashed_password, password):
            if employee.status:
                session['employee_id'] = employee.id  # Store employee's ID in session
                session['logged_in'] = True
                return redirect(url_for('employee_dashboard'))
            else:
                flash('Your account has not been approved yet.', 'warning')
        else:
            flash('Invalid username or password.', 'error')

    return render_template('/employee/login.html')

@app.route('/employee/dashboard')
def employee_dashboard():
    if 'employee_id' not in session:
        flash("Please log in to access the dashboard.", "warning")
        return redirect(url_for('employeLogin'))

    employee_id = session.get('employee_id')
    if not employee_id:
        flash('Login session expired or invalid.', 'error')
        return redirect(url_for('employeLogin'))

    employee = Employee.query.get(employee_id)
    if not employee:
        flash('Employee not found.', 'error')
        return redirect(url_for('employeLogin'))

    # Assuming you have a relationship setup to fetch parcels related to this employee
    parcels = Parcel.query.filter_by(user_id=employee_id).all()

    return render_template('employee/dashboard.html', employee=employee, parcels=parcels)




@app.route('/employee/approve_delivery/<int:parcel_id>', methods=['POST'])
def approve_delivery(parcel_id):
    if 'employee_id' not in session:
        flash("You must be logged in to perform this action.", "warning")
        return redirect(url_for('employee_login'))

    parcel = Parcel.query.get_or_404(parcel_id)
    # Check if the parcel's status is already 'approved'
    if parcel.status == 'approved':
        # Check if delivery has not yet been requested
        if parcel.delivery_requested != 'approved':
            parcel.delivery_requested = 'approved'
        try:
            db.session.commit()
            flash("Delivery request has been approved.", "success")
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error when approving delivery for parcel {parcel_id}: {e}")
            flash("An error occurred while processing your request. Please try again.", "danger")

        else:
            flash("Delivery request is already approved.", "info")
    else:
        flash("Delivery cannot be approved since the parcel status is not 'approved'.", "danger")
    return redirect(url_for('employee_dashboard'))


@app.route('/employee/logout')
def employee_logout():
    session.pop('employee_id', None)  # Remove the employee_id from session
    session['logged_in'] = False
    flash('You have been logged out.', 'info')
    return redirect(url_for('employeLogin'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  
        app.run(debug=True)