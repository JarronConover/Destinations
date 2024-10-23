from django.shortcuts import redirect, render
from django.http import HttpRequest, HttpResponse
from .models import User, Session, Destination
from django.core.exceptions import ObjectDoesNotExist
import secrets

def index(request: HttpRequest):
    recent_destinations = Destination.objects.filter(share_publicly=True).order_by('-id')[:5]

    token = request.COOKIES.get('token')
    is_authenticated = bool(token)

    return render(request, 'core/index.html', {'destinations': recent_destinations, 'is_authenticated': is_authenticated })
    
def user(request: HttpRequest):
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        password = request.POST.get('password')
        password_hash = User.hashPassword(password)

        if '@' not in email:
            error_message = 'Invalid email address'
        
        elif User.objects.filter(email=email).exists():
            error_message = 'Email already exists. Please use a different email.'
        
        elif len(password) < 8:
            error_message = 'Password must be at least 8 characters long'
        
        elif not any(char.isdigit() for char in password):
            error_message = 'Password must contain a number'
        
        if error_message:
            return render(request, 'core/new_user.html', {'error_message': error_message})
        
        user = User.objects.create(name=name, email=email, password_hash=password_hash)
        token = secrets.token_hex(32)
        Session.objects.create(user=user, token=token)

        response = redirect('destinations')
        response.set_cookie("token", token)
        return response
        
    return render(request, 'core/new_user.html', {'error_message': '400 Error: Message was not a POST'})

def new_user(request: HttpRequest):

    token = request.COOKIES.get('token')
    is_authenticated = bool(token)

    return render(request, 'core/new_user.html', {'is_authenticated': is_authenticated})


def sessions(request: HttpRequest):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        password_hash = User.hashPassword(password)

        try: 
            user = User.objects.get(email=email)
            if user.password_hash == password_hash:

                token = secrets.token_hex(32)

                existing_session = Session.objects.filter(user=user).first()
                if existing_session:
                    existing_session.token = token
                    existing_session.save()
                else:
                    Session.objects.create(user=user, token=token)

                response = redirect('destinations')
                response.set_cookie('token', token)
                return response
            else: 
                request.session['error_message'] = 'Incorrect password was provided, please try again'
        except ObjectDoesNotExist:
            request.session['error_message'] = 'User not found'

        return redirect('new_sessions')
    
    request.session['error_message'] = 'Not a POST'
    return redirect('new_sessions')

def sign_in(request: HttpRequest):

    token = request.COOKIES.get('token')
    is_authenticated = bool(token)

    error_message = request.session.pop('error_message', None)

    return render(request, 'core/sign_in.html', {'is_authenticated': is_authenticated, 'error_message': error_message})


def logout(request: HttpRequest):
    token = request.COOKIES.get('token')

    if token:
        Session.objects.filter(token=token).delete()
        request.session['error_message'] = 'You have been logged out successfully'

    response = redirect('/')
    response.delete_cookie('token')

    return response

def destination(request: HttpRequest, destination_id):
    token = request.COOKIES.get('token')
    session = Session.objects.filter(token=token).first()
    user = User.objects.filter(id=session.user_id).first()

    destination = Destination.objects.filter(id=destination_id, user=user).first()

    if destination is None:
        return HttpResponse('Destination not found', status=404)
    
    if request.method == 'POST':
        destination.review = request.POST.get('review')
        destination.rating = request.POST.get('rating')
        destination.share_publicly = request.POST.get('share_publicly')
        destination.save()
        return redirect('destinations')

    return render(request, 'core/destination.html', {'destination': destination})

def destinations(request: HttpRequest):
    token = request.COOKIES.get('token')
    session = Session.objects.filter(token=token).first()
    user = User.objects.filter(id=session.user_id).first()

    if request.method == 'POST':
        name = request.POST.get('name')
        review = request.POST.get('review')
        rating = request.POST.get('rating')
        share_publicly = request.POST.get('share_publicly')
        
        Destination.objects.create(name=name, review=review, rating=rating, share_publicly=share_publicly, user=user)
    
    if user:
        destinations = Destination.objects.filter(user=user)
        return render(request, 'core/destinations.html', {'destinations' : destinations})
    else:
        request.session['error_message'] = 'Please sign in to see your destinations'
        return redirect('new_sessions')

def new_destinations(request: HttpRequest):
    return render(request, 'core/new_destination.html')

def destroy_destination(request: HttpRequest, destination_id):
    token = request.COOKIES.get('token')
    session = Session.objects.filter(token=token).first()
    user = User.objects.filter(id=session.user_id).first()

    destination = Destination.objects.filter(id=destination_id, user=user).first()

    if destination is None:
        return HttpResponse('Destination not found', status=404)
    
    destination.delete()

    return redirect('destinations')
