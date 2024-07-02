# __init__.py

from flask import Flask, make_response,jsonify, request, Request, Response, render_template, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
import subprocess
import pprint

PScmdMain = """
$_version = "16P"

$Global:dhcpserver = "cz11win016p"
$Global:dhcpserverA = "cz11win015p"

$Global:html_Main = @"
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dr.Max DHCP</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
    <link rel="stylesheet" href="/static/dhcp4.css">
    <script src="/static/dhcp4.js"></script>
</head>

<body>

    <div class="sidebar">
        <h2 style="text-align: center;">Buildings</h2>
        <input class="input" id="filterInput" placeholder="Filter...">
        <button id="toggleAllButton">Expand All</button>
        {{MENU}}
    </div>
    <script>sideMenu()</script>

    <div class="content">
        <iframe name="content" style="width: calc(100% - 250px); height: 100vh; top: 0; border: none;"></iframe>
    </div>

</body>

</html>
"@
$Global:html_ReloadButton = "<button onClick='window.location.reload();'>Refresh Data</button>"
$Global:html_AddButton = "<p><form action=`"/dhcp/lease/edit/{{SCOPE}}/{{SCOPE}}`" method=`"get`"><button name=`"AddForm`" class=`"savebtn`">Add</button></form></p>"
$Global:html_EditButton = "<form action=`"/dhcp/lease/edit/{{SCOPE}}/{{IP}}`" method=`"get`"><button name=`"EditForm`" class=`"editbtn`">Edit</button></form>"
$Global:html_form = @"
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <title>EDIT</title>
    <link rel="stylesheet" type="text/css" href="/static/dhcp4.css"/>
</head>
<body>
    <h2>Modify Reservation</h2>
    <p>for Scope {{SCOPEID}}</p>
    <form id="leaseform" method="POST" action="/dhcp/lease/edit">
        <input name="ScopeID" type="hidden" value="{{SCOPEID}}" Id="scope"/>
        <label Id="Name">Lease Name:</label><br>
        <input name="Name" type="text" placeholder="dynamic" value="{{NAME}}" Id="Name"/><br>
        <label Id="IPAddress">IP Address (mandatory):</label><br>
        <input name="IPAddress" type="text" required placeholder="10.0.0.0" value="{{IP}}" Id="IPAddress"/><br>
        <label Id="ClientId">MAC address (mandatory):</label><br>
        <input name="ClientId" type="text" required placeholder="aa-bb-cc-dd-ee-ff" value="{{MAC}}" Id="ClientId"/><br>
        <label Id="Description">Description:</label><br>
        <input name="Description" type="text" placeholder="any helpfull" value="{{DESCRIPTION}}" Id="Description"/><br>
        <input name="submit" type="submit" id="SaveBtn" value="Save" class="savebtn" onclick="this.form.submitted=this.value;"/>
        <input name="submit" type="submit" id="DeleteBtn" value="Delete" class="deletebtn" onclick="this.form.submitted=this.value;"/>
    </form>
</body>
</html>

"@

function Global:Get-Leases {
    param ($Scope)
    Get-DhcpServerv4Lease -ComputerName $Global:dhcpserver -ScopeId $Scope
}

function Global:Get-Lease {
    param ($ip)
    Get-DhcpServerv4Reservation -ComputerName $Global:dhcpserver -IPAddress $ip
}

function Global:Convert-IPToInt32 {
    param (
        [string]$ipAddress
    )
    
    # PÅ™evedenÃ­ Å™etÄ›zce s IP adresou na objekt tÅ™Ã­dy System.Net.IPAddress
    $ip = [System.Net.IPAddress]::Parse($ipAddress)
    
    # ZÃ­skÃ¡nÃ­ bajtÅ¯ IP adresy v reverznÃ­m poÅ™adÃ­
    $bytes = $ip.GetAddressBytes() | ForEach-Object { $_ }
    [Array]::Reverse($bytes)
    
    # PÅ™evod bajtÅ¯ na int32
    $int32Value = [System.BitConverter]::ToInt32($bytes, 0)
    
    return $int32Value
}
"""

app = Flask(__name__)

# ----------------------   Flask Login   -----------------------
app.secret_key = 'your_secret_key'

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
            }, 3500);  // Redirect after 1 second
        </script>
        ''',
        401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'}
    )

@app.route('/logout_complete')
def logout_complete():
    return redirect(url_for('login'))


# ----------------------   Flask Routes   -----------------------

'''
@app.before_request
def before_request():
    print("before_request executing!")

    # # -----
    # # From Flask authentication
    # if current_user.is_authenticated:
    #     flash("You are already logged in.", "info")
    #     return redirect(url_for("core.home"))
    # # -----

     # # -----
    # # curl -i -H 'x-api-key: asoidewfoef' http://localhost:5000
    # headers = request.headers
    # auth = headers.get("X-Api-Key")
    # if auth == 'asoidewfoef':
    #     return jsonify({"message": "OK: Authorized"}), 200
    # else:
    #     return jsonify({"message": "ERROR: Unauthorized"}), 401
    # # -----

    return 'UNAUTHORIZED', 401, {'www-authenticate': 'Negotiate'}

    @app.roure('/logout')

@login_required
def logout():
    logout_user()
    flash("You were logged out.", "success")
    return redirect(url_for("login"))
    # # V Jinja lze pak pomoci kategorie (2. parametr u flash() ) pridavat class pro formatovani:
    # {% with messages = get_flashed_messages(with_categories=true) %}
    #   {% if messages %}
    #     {% for category, message in messages %}
    #       <div class="alert {{ category }}"> {{ message|capitalize }} </div>
    #     {% endfor %}
    #   {% endif %}
    # {% endwith %}
'''

@app.route('/')
@login_required
def index():
  return redirect(url_for('dhcp'))


# Boilerplate for PowerShell calls
# --------------------------------
'''
@app.route('/dhcp/')
def dhcp():
  PScmd = PScmdMain
  PScmd += """$var = '""" + var + """'
"""
  PScmd += """
    $html
"""

  try:
    # Can add parametr -Verb RunAs to run as administrator
    # output = subprocess.check_output(["powershell", "-ExecutionPolicy", "Bypass", "-NoProfile", "-command", PScmd], text=True)
    # Example: https://stackoverflow.com/questions/47380378/run-process-as-admin-with-subprocess-run-in-python
    #
    output = subprocess.check_output(["powershell", "-command", PScmd], text=True)
    response = make_response(output, 200)

  except subprocess.CalledProcessError as e:
    output = {"message": "PowerShell subprocess failed", "returncode": e.returncode}
    response = make_response(output, 401)

  # Final response
  # response.headers["Content-Type"] = "application/json"
  return response
'''
# --------------------------------

@app.route('/dhcp/')
def dhcp():
  PScmd = PScmdMain
  PScmd += """
    # Write-Host("DeBUG: index.html START")

    # Side Navigation
    $html_nav = ""

    # # SuperScope version BEGIN
    # $SuperScopes = Get-DhcpServerv4SuperScope -ComputerName $Global:dhcpserver
    # if ($SuperScopes -eq 0) {
    #     $Response.SetStatusCode(404)
    #     $Response.Send("Not found!")
    #     return
    # }

    # foreach ($SuperScope in $SuperScopes) {
    #     $html_nav += "<div class=`"menu-item`">" + $SuperScope.SuperscopeName + "<i class=`"fa fa-caret-down`"></i></div><div class=`"submenu`">`r"
    #     foreach ($Scope in $SuperScope.ScopeID) {
    #         $ip = $Scope.IPAddressToString
    #         $html_nav += "<div class=`"submenu-item`" data-href=`"/dhcp/lease/" + $ip + "`">" + $ip + "</div>`r"
    #     }
    #     $html_nav += "</div>`r"
    # }
    # # SuperScope version END
    
    # Scope version BEGIN
    $Scopes = Get-DhcpServerv4Scope -ComputerName $Global:dhcpserver | Sort-Object Description, { Convert-IPToInt32 -ipAddress $_.ScopeId }
    # if ($Scopes -eq 0) {
    #     $Response.SetStatusCode(404)
    #     $Response.Send("Not found!")
    #     return
    # }

    # Filling the associative array for Scope tree by Scope.Description
    $ScopeTree = @{}
    foreach ($Scope in $Scopes) {
        if (-not $ScopeTree.ContainsKey($Scope.Description)) {
            $ScopeTree[$Scope.Description] = @()
        }
        $ScopeTree[$Scope.Description] += $Scope
    }

    # VypsÃ¡nÃ­ setÅ™Ã­dÄ›nÃ½ch rozsahÅ¯ jako strom
    foreach ($description in $ScopeTree.Keys | Sort-Object) {
        # Write-Host "$description"
        $html_nav += "<div class=`"menu-item`">" + $description + "<i class=`"fa fa-caret-down`"></i></div><div class=`"submenu`">`r"
        foreach ($Scope in $ScopeTree[$description]) {
            # Write-Host "  $($Scope.Name) (ID: $($Scope.ScopeId))"
            # $ip = $Scope.ScopeId.IPAddressToString
            $ip = $Scope.ScopeId
            $name = $Scope.Name.split("-",4)[-1]
            # $html_nav += "<div class=`"submenu-item`" data-href=`"/dhcp/lease/" + $ip + "`">" + $ip + "</div>`r"
            $html_nav += "<div class=`"submenu-item`" data-href=`"/dhcp/lease/" + $ip + "`">" + $ip + ":" + $name + "</div>`r"
        }
        $html_nav += "</div>`r"
    }
    # Scope version END

    $html_nav += "<form action=`"/logout`" method=`"get`"><button name=`"Logout`" class=`"editbtn`">Logout</button></form>`r"
    
    $html_nav += "<pre>version " + $_version + "</pre>`r"

    # Add navbar to main page
    $html = $Global:html_Main.Replace("{{MENU}}", $html_nav)

    $html
"""

  try:
    output = subprocess.check_output(["powershell", "-command", PScmd], text=True)
    response = make_response(output, 200)

  except subprocess.CalledProcessError as e:
    output = {"message": "PowerShell subprocess failed", "returncode": e.returncode}
    response = make_response(output, 401)

  # Final response
  return response

@app.route('/dhcp/lease/<id>')
def dhcp_lease(id):
  PScmd = PScmdMain
  PScmd += """$id = '""" + id + """'
"""
  PScmd += """
    $leases = Global:Get-Leases($id)
    $scopeInfo = Get-DhcpServerv4Scope -Scope $id | ConvertTo-Html -Fragment -As List -Property Name,ScopeId,SubnetMask,StartRange,EndRange,LeaseDuration
    $scopeInfoExclude = Get-DhcpServerv4ExclusionRange -ScopeId $id | ConvertTo-Html -Fragment -Property StartRange,EndRange -PreContent "<h3>Excluded</h3>" -PostContent "<br>"
    $data = $leases | Select-Object `
    @{Name = "IP Address"; Expression = { $_.IPAddress } },
    @{Name = "MAC"; Expression = { $_.ClientId } },
    @{Name = "State"; Expression = { $_.AddressState } },
    @{Name = "Lease Name"; Expression = { $_.HostName } },
    @{Name = "Expiry"; Expression = { $_.LeaseExpiryTime } },
    Description,
    @{Name         = "Modify";
        Expression = { $Global:html_EditButton.Replace("{{SCOPE}}", $id).Replace("{{IP}}", $_.IPAddress) } 
    }

    Add-Type -AssemblyName System.Web
    $html = [System.Web.HttpUtility]::HtmlDecode(($data | ConvertTo-Html `
                -CssUri "/static/dhcp4.css" `
                -Body "<h2>DHCP Scope</h2>" `
                -PreContent ($Global:html_ReloadButton + "<p></p>" + $scopeInfo + $scopeInfoExclude + "<h3>Leases</h3>" + $Global:html_AddButton.Replace("{{SCOPE}}", $id)) `
        ))

    $html
"""

  try:
    output = subprocess.check_output(["powershell", "-command", PScmd], text=True)
    response = make_response(output, 200)

  except subprocess.CalledProcessError as e:
    output = {"message": "PowerShell subprocess failed", "returncode": e.returncode}
    response = make_response(output, 401)

  # Final response
  return response

@app.route('/dhcp/lease/edit/<ScopeId>/<IP>')
def dhcp_lease_edit_scope(ScopeId, IP):
  print(dict(request.args))
  if 'EditForm' in request.args:
    button = "EditForm"
  elif 'AddForm' in request.args:
    button = "AddForm"
  else:
    button = ""

  PScmd = PScmdMain
  PScmd += """$ScopeId = '""" + ScopeId + """'
"""
  PScmd += """$ip = '""" + IP + """'
"""
  PScmd += """$button = '""" + button + """'
"""
  PScmd += """
    if ($button -eq "EditForm") {
        $lease = Get-Lease($ip)
        if ($lease.Count -eq 0) {
        #     $Response.SetStatusCode(404)
        #     $Response.Send("Not found!")
            return "Not found!"
        }
        else {
            $html = $Global:html_form.Replace(
                "{{SCOPEID}}", $ScopeID).Replace(
                "{{NAME}}", $lease.Name).Replace(
                "{{IP}}", $ip).Replace(
                "{{MAC}}", $lease.ClientId).Replace(
                "{{DESCRIPTION}}", $lease.Description)
        }
    }
    else {
        $html = $Global:html_form.Replace(
            "{{SCOPEID}}", $ScopeID).Replace(
            "{{NAME}}", "").Replace(
            "{{IP}}", $ip).Replace(
            "{{MAC}}", "").Replace(
            "{{DESCRIPTION}}", "")
    }
    $html
"""

  try:
    output = subprocess.check_output(["powershell", "-command", PScmd], text=True)
    response = make_response(output, 200)

  except subprocess.CalledProcessError as e:
    output = {"message": "PowerShell subprocess failed", "returncode": e.returncode}
    response = make_response(output, 401)

  # Final response
  # response.headers["Content-Type"] = "application/json"
  return response

@app.route('/dhcp/lease/edit/', methods = ['POST'])
def dhcp_lease_edit():
  # return request.get_data() # ScopeID=10.34.2.0&Name=CISCO+Webex&IPAddress=10.34.2.134&ClientId=ac-4a-67-fd-63-97&Description=CISCO+Webex&submit=Save
  # return request.form
  BodyString = request.get_data().decode("utf-8")
  # UserName = "admsrb"
  UserName = current_user.id
  PScmd = PScmdMain
  PScmd += """$BodyString = '""" + BodyString + """'
"""
  PScmd += """$UserName = '""" + UserName + """'
"""
  PScmd += """
    $html = ""
    $Form = $BodyString.Split("&") | ConvertFrom-StringData

    # Checked IP
    [System.Net.IPAddress]$IPAddress = $Form.IPaddress
    # Get all groups that can manipulate with IP
    $ScopeAdminGroups = import-csv "./data/admin-groups.csv" `
    | ForEach-Object {
        # Write-Host($_.Group + ":"+$_.Subnet)

        $net, $mask_bits = $_.Subnet.Split("/")
        # Write-Host($net+":"+$mask_bits)

        # $ip = [System.Net.IPAddress]$net
        # $mask = ([System.Net.IPAddress]([UInt32]([Math]::Pow(2, $mask_bits) - 1) * [Math]::Pow(2, (32 - $mask_bits)))).IPAddressToString
        $mask = [System.Net.IPAddress]([UInt32]([Math]::Pow(2, $mask_bits) - 1) * [Math]::Pow(2, (32 - $mask_bits)))
        # $subnet = [System.Net.IPAddress]($ip.address -band $mask.address)

        [System.Net.IPAddress]$Subnet = $net
        [System.Net.IPAddress]$SubnetMask = $mask

        if ($Subnet.Address -eq ($IPaddress.Address -band $SubnetMask.Address)) {
            $_.Group
        }
    } `
    | Select-Object -unique
    Remove-Variable -Name $IPAddress -Force -ErrorAction SilentlyContinue

    # get all user groups that a user is a member of and select intersection of sets
    $ScopeUserGroups = Get-ADPrincipalGroupMembership $UserName | Select-Object Name | Where-Object { $_.Name -in $ScopeAdminGroups }

    if (-not $ScopeUserGroups) {
        # $Response.StatusCode = 401
        # $Response.Send("Unauthorized")
        $html = "Unauthorized"
        $html
        return
    }
    # Authorization END

    # Submit form
    if ($Form.submit -eq "Save") {
        Add-Type -AssemblyName System.Web
        $reservationParams = @{
            ComputerName = $Global:dhcpserverA
        }

        if ($Form.IPaddress -ne "") {
            $reservationParams.IPaddress = $Form.IPaddress
        }
        if ($Form.Name -ne "") {
            $reservationParams.Name = [System.Web.HttpUtility]::UrlDecode($Form.Name)
        }
        if ($Form.Description -ne "") {
            $reservationParams.Description = [System.Web.HttpUtility]::UrlDecode($Form.Description)
        }
        if ($Form.ClientId -ne "") {
            $reservationParams.ClientId = $Form.ClientId
        }
        # Write-Host("saving...")
        Try {
            # Write-Host Set-DhcpServerv4Reservation @reservationParams
            Set-DhcpServerv4Reservation @reservationParams
            $html = "Set"
        }
        Catch {
            # if ($Form.ScopeID -ne "") { $reservationParams.ScopeId = $Form.ScopeID }
            # Write-Host Add-DhcpServerv4Reservation @reservationParams
            Remove-DhcpServerv4Reservation -ErrorAction SilentlyContinue -ComputerName $Global:dhcpserverA -ClientId $Form.ClientId -ScopeId $Form.ScopeID
            Add-DhcpServerv4Reservation @reservationParams -ScopeId $Form.ScopeID
            $html = "Add"
        }
    }
    elseif ($Form.submit -eq "Delete") {
        # Write-Host("deleting... " + $Form.IPaddress)
        Try {
            Remove-DhcpServerv4Reservation -ComputerName $Global:dhcpserverA   -IPaddress $Form.IPaddress
            $html = "Delete"
        }
        Catch {
            $html = "NotDelete"
        }
    }
    # Write-Host("syncing...")
    Invoke-DhcpServerv4FailoverReplication -Force -ComputerName $Global:dhcpserverA -ScopeId $Form.ScopeID

    # $redirect = $Request.RawRequest.UrlReferrer
    # $Response.StatusCode = 303 #  redirect after a PUT or a POST
    # $Response.SetHeader("Location", ("/dhcp/lease/" + $Form.ScopeID))
    # $Response.Send("")
    $html
"""

  try:
    output = subprocess.check_output(["powershell", "-command", PScmd], text=True)
    response = make_response(output, 200)

  except subprocess.CalledProcessError as e:
    output = {"message": "PowerShell subprocess failed", "returncode": e.returncode}
    response = make_response(output, 401)

  # Final response
  return response

@app.route('/dhcp/lease/cleanbad/', methods = ['POST'])
def dhcp_lease_cleanbad():
  PScmd = PScmdMain
  PScmd += """
      Get-DhcpServerv4Scope -ComputerNam $Global:dhcpserver | Remove-DhcpServerv4Lease -ComputerNam $Global:dhcpserver -BadLeases
"""

  try:
    output = subprocess.check_output(["powershell", "-command", PScmd], text=True)
    response = make_response(output, 200)

  except subprocess.CalledProcessError as e:
    output = {"message": "PowerShell subprocess failed", "returncode": e.returncode}
    response = make_response(output, 401)

  # Final response
  # response.headers["Content-Type"] = "application/json"
  return response



# # -------------------- API
# # SCOPE ROUTES
# @app.route('/dhcp/api/scope/<scope>')
# def Scope(scope):
#   PScmd = """Get-DhcpServerv4Scope -ComputerName cz11win016p -ScopeId """ + scope + """ | Select-Object  `
#     SuperscopeName,
#     Description,
#     Name,
#     @{Name = "ScopeId"; Expression = { $_.ScopeId.IPAddressToString } },
#     State,
#     @{Name = "SubnetMask"; Expression = { $_.SubnetMask.IPAddressToString } },
#     @{Name = "StartRange"; Expression = { $_.StartRange.IPAddressToString } },
#     @{Name = "EndRange"; Expression = { $_.EndRange.IPAddressToString } },
#     @{Name = "LeaseDuration"; Expression = { $_.LeaseDuration.TotalMinutes } } | ConvertTo-Json"""

#   try:
#     output = subprocess.check_output(["powershell", "-command", PScmd], text=True)
#     response = make_response(output, 200)

#   except subprocess.CalledProcessError as e:
#     output = jsonify({"message": "PowerShell subprocess failed", "returncode": e.returncode})
#     response = make_response(output, 401)

#   # Final response
#   response.headers["Content-Type"] = "application/json"
#   return response

# @app.route('/dhcp/api/scope/exlude/<scope>')
# def ScopeExclude(scope):
#   PScmd = """Get-DhcpServerv4ExclusionRange -ComputerName glwsnenettst01p -ScopeId """ + scope + """ | Select-Object  `
#     @{Name = "ScopeId"; Expression = { $_.ScopeId.IPAddressToString } },
#     @{Name = "StartRange"; Expression = { $_.StartRange.IPAddressToString } },
#     @{Name = "EndRange"; Expression = { $_.EndRange.IPAddressToString } } | ConvertTo-Json"""

#   try:
#     output = subprocess.check_output(["powershell", "-command", PScmd], text=True)
#     response = make_response(output, 200)

#   except subprocess.CalledProcessError as e:
#     output = jsonify({"message": "PowerShell subprocess failed", "returncode": e.returncode})
#     response = make_response(output, 401)

#   # Final response
#   response.headers["Content-Type"] = "application/json"
#   return response

# # LEASE ROUTES
# @app.route('/dhcp/api/lease/<scope>')
# def Lease(scope):
#   PScmd = """Get-DhcpServerv4Lease -ComputerName cz11win016p -ScopeId """ + scope + """ | Select-Object  `
#     @{Name = "IPAddress"; Expression = { $_.IPAddress.IPAddressToString } },
#     @{Name = "MAC"; Expression = { $_.ClientId } },
#     @{Name = "State"; Expression = { $_.AddressState } },
#     @{Name = "Hostname"; Expression = { $_.HostName } },
#     @{Name = "Expiry"; Expression = { $_.LeaseExpiryTime.DateTime } },
#     @{Name = "ScopeId"; Expression = { $_.ScopeId.IPAddressToString } },
#     DnsRegistration,Description | ConvertTo-Json"""

#   try:
#     output = subprocess.check_output(["powershell", "-command", PScmd], text=True)
#     response = make_response(output, 200)

#   except subprocess.CalledProcessError as e:
#     output = jsonify({"message": "PowerShell subprocess failed", "returncode": e.returncode})
#     response = make_response(output, 401)

#   # Final response
#   response.headers["Content-Type"] = "application/json"
#   return response

# # PAGES
# @app.route('/table')
# def Table():
#   return render_template("table.html")
