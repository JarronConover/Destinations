from django.urls import path
from . import views

urlpatterns = [
        path('', views.index, name='index'),
        path('users/new/', views.new_user, name='new_user'),
        path('sessions/new/', views.sign_in, name='new_sessions'),
        path('users/', views.user, name='users'),
        path('sessions/', views.sessions, name='sessions'),
        path('sessions/destroy/', views.logout, name='logout'),
        path('destinations/', views.destinations, name='destinations'),
        path('destinations/new/', views.new_destinations, name='new_destinations'),
        path('destinations/<int:destination_id>/', views.destination, name='destination'),
        path('destinations/<int:destination_id>/destroy/', views.destroy_destination, name='destroy_destination'),
        
]
