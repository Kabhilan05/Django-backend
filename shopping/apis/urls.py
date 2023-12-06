from django.urls import path
from .views import register,getusers,getuser,user_login,user_logout

urlpatterns = [
    path('register/',register, name="add_user"),
    path('getusers/<int:page>/',getusers,name="get_all_users"),
    path('getuser/<str:pk>/',getuser,name="get_user"),
    path('login/',user_login,name="login"),
    path('logout/',user_logout,name="logout"),

 
]