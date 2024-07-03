# DhcpServerApi.py

import subprocess
import json
# import ctypes
# import sys
# import os
import pprint

class DhcpServer:
    """
    # Example
    dhcp_server = DhcpServer('cz11win015p') # or cz11win016p

    leases_result = dhcp_server.ScopeGet()
    if leases_result['error'] is None:
        print("Leases:", leases_result['data'])
    else:
        print(f"Error occurred with code: {leases_result['error']}")
    """
    def __init__(self, server):
        self.GlobalDhcpServer = server

    def __powershell_cmd(self, command, nocims=True, **kwargs):

        # def is_admin():
        #     try:
        #         return ctypes.windll.shell32.IsUserAnAdmin()
        #     except:
        #         return False

        def replace_IPAddressToString(data):
            if isinstance(data, list):
                return [replace_IPAddressToString(item) for item in data]
            elif isinstance(data, dict):
                if 'IPAddressToString' in data:
                    return data['IPAddressToString']
                else:
                    return {key: replace_IPAddressToString(value) for key, value in data.items()}
            else:
                return data

        cims = kwargs.get('cims', False)
        if cims:
            full_command = f'{command} -ComputerName {self.GlobalDhcpServer} | ConvertTo-Json -Compress'
        else:
            full_command = f'{command} -ComputerName {self.GlobalDhcpServer} | Select-Object -Property * -ExcludeProperty Cim* | ConvertTo-Json -Compress'

        # Can add parametr -Verb RunAs to run as administrator
        # output = subprocess.check_output(["powershell", "-ExecutionPolicy", "Bypass", "-NoProfile", "-command", PScmd], text=True)
        # Example: https://stackoverflow.com/questions/47380378/run-process-as-admin-with-subprocess-run-in-python
        try:    
            # if not is_admin():
            #     # Spuštění PowerShellu jako administrátor
            #     script = f'powershell -Command "{full_command}"'
            #     params = f'runas powershell.exe {script}'
            #     ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f' /c {script}', None, 1)
            #     return {'data': None, 'error': 'Nezdařilo se spustit PowerShell s administrátorskými právy.'}

            output = subprocess.run(
                ['powershell', '-Command', full_command],
                timeout=120, capture_output=True, text=True, check=True
            )

            if output.stdout == "" or output.stdout is None:
                result = None
                return {'data': None, 'error': 'NO DATA'}

            result = replace_IPAddressToString(json.loads(output.stdout))
            # result = json.loads(output.stdout)

            # Return result as list
            if isinstance(result, list):
                return {'data': result, 'error': None}
            else:
                return {'data': [result], 'error': None}            
        
        except subprocess.CalledProcessError as e:
            # print(f"Error: {e.stderr}")
            return {'data': None, 'error': e.returncode}  # None data

    # --- scopes ---
    def SuperScopeGet(self, scope=None, **kwargs):
        command = f'Get-DhcpServerv4SuperScope'
        if scope:
            command += f' -SuperscopeName {scope}'
        return self.__powershell_cmd(command, **kwargs)

    def ScopeGet(self, scope=None, **kwargs):
        command = f'Get-DhcpServerv4Scope'
        if scope:
            command += f' -ScopeId {scope}'
        return self.__powershell_cmd(command, **kwargs)

    # --- scope options ---
    def ExclusionRangeGet(self, scope=None, **kwargs):
        command = f'Get-DhcpServerv4ExclusionRange'
        if scope:
            command += f' -ScopeId {scope}'
        return self.__powershell_cmd(command, **kwargs)

    # --- leases ---
    # function Global:Get-Leases
    def LeaseGet(self, scope, ip=None, **kwargs):
        command = f'Get-DhcpServerv4Lease -ScopeId {scope}'
        if ip:
            command += f' -IPAddress {ip}'
        return self.__powershell_cmd(command, **kwargs)

    def Lease_CleanBad(self, scope=None, **kwargs):
        command = f'Get-DhcpServerv4Scope'
        if scope:
            command += f' -ScopeId {scope}'
        command += f' | Remove-DhcpServerv4Lease -ComputerNam {self.GlobalDhcpServer} -BadLeases'
        return self.__powershell_cmd(command, **kwargs)

    # --- reservations ---
    # function Global:Get-Lease
    def ReservationGet(self, scope, ip=None, **kwargs):
        command = f'Get-DhcpServerv4Reservation -ScopeId {scope}'
        if ip:
            command += f' -IPAddress {ip}'
        return self.__powershell_cmd(command, **kwargs)

    def ReservationDel(self, ip=None, **kwargs):
        command = f'Get-DhcpServerv4Reservation'
        # Remove-DhcpServerv4Reservation -ErrorAction SilentlyContinue -ComputerName $Global:dhcpserverA -ClientId $Form.ClientId -ScopeId $Form.ScopeID
        if ip:
            command += f' -IPAddress {ip}'
        return self.__powershell_cmd(command, **kwargs)

    def ReservationAdd(self, ip=None, **kwargs):
        command = f'Get-DhcpServerv4Reservation'
        # Add-DhcpServerv4Reservation @reservationParams -ScopeId $Form.ScopeID
        if ip:
            command += f' -IPAddress {ip}'
        return self.__powershell_cmd(command, **kwargs)

    def ReservationSet(self, ip=None, name=None, description=None, clientID=None, **kwargs):
        command = f'Set-DhcpServerv4Reservation'
        if ip:
            command += f' -IPAddress {ip}'
        if name:
            command += f' -Name {name}'
        if description:
            command += f' -Description {description}'
        if clientID:
            command += f' -ClientId {clientID}'
        return self.__powershell_cmd(command, **kwargs)

    # --- replication ---
    def FailoverReplication(self, scope=None, force=None, **kwargs):
        command = f'Invoke-DhcpServerv4FailoverReplication'
        if force:
            command += f' -Force'
        if scope:
            command += f' -ScopeId {scope}'
        return self.__powershell_cmd(command, **kwargs)

def __init__():
    pass
