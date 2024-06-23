import subprocess
from channels.generic.websocket import WebsocketConsumer
import threading

class PowerShellConsumer(WebsocketConsumer):
    def connect(self):
        self.accept()
        self.process = subprocess.Popen(['powershell.exe'], 
                                        stdin=subprocess.PIPE, 
                                        stdout=subprocess.PIPE, 
                                        stderr=subprocess.PIPE, 
                                        text=True, 
                                        bufsize=1, 
                                        universal_newlines=True)
        threading.Thread(target=self.read_output, daemon=True).start()

    def disconnect(self, close_code):
        self.process.terminate()

    def receive(self, text_data):
        self.process.stdin.write(text_data + '\n')
        self.process.stdin.flush()

    def read_output(self):
        for line in iter(self.process.stdout.readline, ''):
            self.send(text_data=line)
        self.process.stdout.close()
