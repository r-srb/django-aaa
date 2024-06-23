from django.shortcuts import render

# Create your views here.

def powershell(request):
    return render(request, 'powershell.html')
