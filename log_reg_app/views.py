from django.shortcuts import render, redirect
from django.contrib import messages
from .models import User
import bcrypt


def index(request):
    request.session.flush()
    return render(request, "index.html")


def register(request):
    errors = User.objects.user_validator(request.POST)
    if len(errors) > 0:
        for key, value in errors.items():
            messages.error(request, value, extra_tags = 'registration')
        return redirect('/')
    else:
        password = request.POST['reg_password']
        psw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        user = User.objects.create(
            first_name=request.POST['first_name'],
            last_name=request.POST['last_name'],
            email=request.POST['reg_email'],
            password=psw_hash
        )
        request.session['user_id'] = user.id
        return redirect('/success')


def success(request):
    if 'user_id' not in request.session:
        return redirect('/')
    user = User.objects.get(id=request.session['user_id'])
    context = {
        'first_name': user.first_name,
    }
    return render(request, "success.html", context)


def login(request):
    errors = User.objects.login_validator(request.POST)
    if len(errors) > 0:
        for key, value in errors.items():
            messages.error(request, value, extra_tags = 'login')
        return redirect('/')
    else:
        user_list = User.objects.filter(email=request.POST['log_email'])
        if len(user_list) != 0:
            logged_user = user_list[0]
            if bcrypt.checkpw(request.POST['log_password'].encode(), logged_user.password.encode()):
                request.session['user_id'] = logged_user.id
                return redirect('/success')
        else:
            messages.error(
                request, "We couldn't find matching email. Please enter correct email or register")
            return redirect('/')


def logout(request):
    request.session.flush()
    return redirect('/')
