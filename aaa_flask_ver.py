'''
Chtěl bych v Django použít externí autentizaci uživatelů jako ji používám teď ve Flask.

a z externího zdroje získavat seznam skupin, v kterých je uživatel přiřazen. V Django mít pak definované role, které by měly přiřazené skupiny získané z externího zdroje. Tyto role pak využívat v Django standardně, jako by byly Django nativní.
'''

from flask import Flask, request, Response, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
import subprocess

app = Flask(__name__)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Specify the login view name

# PowerShell commands regarding Users and Groups
# Examples:
# Get-ADGroupMember -Identity GL-SG-NetGlobalAdmins
# Get-ADUser -Properties memberof -Identity admsrb
# Get-ADPrincipalGroupMembership -Identity admsrb
# (new-object directoryservices.directoryentry "", $Name, $Password).psbase.name -ne $null

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

def check_auth(username, password):
    PScmd = "(new-object directoryservices.directoryentry \"\", \"%s\", \"%s\").psbase.name -ne $null" % (username, password)
    try:
        output = subprocess.check_output(["powershell", "-command", PScmd], text=True).strip()
        if output == "True":
            user_obj = User(username)
            login_user(user_obj)
            return True
        else:
            return False
    except subprocess.CalledProcessError:
        return False

def authenticate():
    auth = request.authorization
    if not auth or not check_auth(auth.username, auth.password):
        return Response('Could not verify your access level for that URL.\nYou have to login with proper credentials', 401,
            {'WWW-Authenticate': 'Basic realm="Login Required"'}
        )
    return None

@app.route('/login')
def login():
    auth_response = authenticate()
    if auth_response:
        return auth_response
    return redirect(url_for('index'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    # Redirect to login page after logging out
    return Response('''
        <p>Logged out! Redirecting...</p>
        <script>
            setTimeout(function() {
                window.location.href = "/logout_complete";
            }, 3500);  // Redirect after 3.5 second
        </script>
        ''',
        401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'}
    )

@app.route('/logout_complete')
def logout_complete():
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
  return "Hello world!"

if __name__ == "__main__":
    app.run(debug=True, host = '127.0.0.1', port = 80)
