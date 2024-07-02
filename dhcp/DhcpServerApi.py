# DhcpServerApi.py

import subprocess
import json
import pprint

class DhcpServer:
    """
    # Example
    dhcp_server = DhcpServer('cz11win015p') # or cz11win016p

    leases_result = dhcp_server.get_leases()
    if leases_result['error'] is None:
        print("Leases:", leases_result['data'])
    else:
        print(f"Error occurred with code: {leases_result['error']}")
    """
    def __init__(self, server):
        self.GlobalDhcpServer = server

    def __powershell_cmd(self, command):
        # Can add parametr -Verb RunAs to run as administrator
        # output = subprocess.check_output(["powershell", "-ExecutionPolicy", "Bypass", "-NoProfile", "-command", PScmd], text=True)
        # Example: https://stackoverflow.com/questions/47380378/run-process-as-admin-with-subprocess-run-in-python
        try:
            full_command = f'{command} -ComputerName {self.GlobalDhcpServer} | ConvertTo-Json'
            result = subprocess.run(
                ['powershell', '-Command', full_command],
                capture_output=True, text=True, check=True
            )
            return {'data': json.loads(result.stdout), 'error': None}  # None error
        except subprocess.CalledProcessError as e:
            print(f"Error: {e.stderr}")
            return {'data': None, 'error': e.returncode}  # None data

    # --- scopes ---
    def SuperScopeGet(self, scope=None):
        command = f'Get-DhcpServerv4SuperScope'
        if scope:
            command += f' -ScopeId {scope}'
        return self.__powershell_cmd(command)

    def ScopeGet(self, scope=None):
        command = f'Get-DhcpServerv4Scope'
        if scope:
            command += f' -ScopeId {scope}'
        return self.__powershell_cmd(command)

    # --- scope options ---
    def ExclusionRangeGet(self, scope=None):
        command = f'Get-DhcpServerv4ExclusionRange'
        if scope:
            command += f' -ScopeId {scope}'
        return self.__powershell_cmd(command)

    # --- leases ---
    # function Global:Get-Leases
    def LeaseGet(self, scope=None):
        command = f'Get-DhcpServerv4Lease'
        if scope:
            command += f' -ScopeId {scope}'
        return self.__powershell_cmd(command)

    def Lease_CleanBad(self, scope=None):
        command = f'Get-DhcpServerv4Scope'
        if scope:
            command += f' -ScopeId {scope}'
        command += f' | Remove-DhcpServerv4Lease -ComputerNam {self.GlobalDhcpServer} -BadLeases'
        return self.__powershell_cmd(command)

    # --- reservations ---
    # function Global:Get-Lease
    def ReservationGet(self, ip=None):
        command = f'Get-DhcpServerv4Reservation'
        if ip:
            command += f' -IPAddress {ip}'
        return self.__powershell_cmd(command)

    def ReservationDel(self, ip=None):
        command = f'Get-DhcpServerv4Reservation'
        # Remove-DhcpServerv4Reservation -ErrorAction SilentlyContinue -ComputerName $Global:dhcpserverA -ClientId $Form.ClientId -ScopeId $Form.ScopeID
        if ip:
            command += f' -IPAddress {ip}'
        return self.__powershell_cmd(command)

    def ReservationAdd(self, ip=None):
        command = f'Get-DhcpServerv4Reservation'
        # Add-DhcpServerv4Reservation @reservationParams -ScopeId $Form.ScopeID
        if ip:
            command += f' -IPAddress {ip}'
        return self.__powershell_cmd(command)

    def ReservationSet(self, ip=None, name=None, description=None, clientID=None):
        command = f'Set-DhcpServerv4Reservation'
        if ip:
            command += f' -IPAddress {ip}'
        if name:
            command += f' -Name {name}'
        if description:
            command += f' -Description {description}'
        if clientID:
            command += f' -ClientId {clientID}'
        return self.__powershell_cmd(command)

    # --- replication ---
    def FailoverReplication(self, scope=None, force=None):
        command = f'Invoke-DhcpServerv4FailoverReplication'
        if force:
            command += f' -Force'
        if scope:
            command += f' -ScopeId {scope}'
        return self.__powershell_cmd(command)

def __init__():
    pass
