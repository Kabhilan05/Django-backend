from django.shortcuts import render
from .models import CustomUser
from django.contrib.auth import authenticate, login,logout
from rest_framework.response import Response
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.authtoken.models import Token
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
# from django.views.decorators.csrf import csrf_protect
from django.contrib.auth.models import Group, Permission
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger

# from ratelimit.decorators import ratelimit
from django_ratelimit.decorators import ratelimit

# for mail 
from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver
from django.core.mail import EmailMessage
from django.conf import settings

from .serializer import UserSerializer


# Create your views here.



def create_groups_and_permissions():
    # Create admin group
    admin_group, created = Group.objects.get_or_create(name='Admin Group')

    # Assign permissions to the admin group (customize based on your needs)
    admin_permissions = [
        Permission.objects.get(codename='add_customuser'),
        Permission.objects.get(codename='change_customuser'),
        Permission.objects.get(codename='delete_customuser'),
        # Add more permissions as needed
    ]
    admin_group.permissions.set(admin_permissions)

    # Create user group
    user_group, created = Group.objects.get_or_create(name='User Group')

    # Assign permissions to the user group (customize based on your needs)
    user_permissions = [
        # Define permissions for regular users
    ]
    user_group.permissions.set(user_permissions)

# Call the function to create groups and assign permissions
create_groups_and_permissions()




#Register
@api_view(["POST"])
def register(request):
    try:
        createUser = CustomUser.objects.create(username=request.data.get('username'),email=request.data.get('email'))
        createUser.set_password(request.data.get('password'))
        

        # Assign the user to the 'User Group' by default
        user_group = Group.objects.get(name='User Group')

        createUser.groups.add(user_group) 
        createUser.save()
        
#:{str(createUser.get_all_permissions)}
        return Response(f"User created successfully")
    except Exception as e: 
        return Response(f"There is an error: {str(e)}") 




#Get all users
@api_view(["GET"])
@ratelimit(key='user', rate='5/m', block=True)
def getusers(request,page):
    try:
        res = request.user
        if res.groups.filter(name='Admin Group').exists():
            users = CustomUser.objects.all()
            users_per_page = 5
            paginator = Paginator(users, users_per_page)
            # page = request.GET.get('page')
            try:
                users_page = paginator.page(page)
                serialiazer  = UserSerializer(users_page,many = True)
                
            except PageNotAnInteger:
                users_page = paginator.page(1)
                serialiazer  = UserSerializer(users_page,many = True)
            except EmptyPage:
                users = paginator.page(paginator.num_pages)
                serialiazer  = UserSerializer(users_page,many = True)

            return Response(serialiazer.data)
        else:
            return Response("Your Do not have permission")

    except Exception as e:
        return Response(f"There is an error: {str(e)}") 



# Protected Route
@api_view(["GET"])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
@ratelimit(key='user', rate='5/m', block=True)
def getuser(request,pk):
    try:
        res = request.user
        user = CustomUser.objects.get(id = pk)
        if res.groups.filter(name='Admin Group').exists() or res == user:
            serialiazer  = UserSerializer(user,many = False)
            return Response(serialiazer.data)
        else:
            return Response("Your Do not have permission")

    except Exception as e:
        return Response(f"There is an error: {str(e)}") 
    


#Login

@api_view(["POST"])
@ratelimit(key='user', rate='5/m', block=True)
# @csrf_protect 
# @permission_classes([IsAuthenticated])
def user_login(request):
    try:
        username = request.data.get('username')
        password = request.data.get('password')

        # Authenticate user
        user = authenticate(request, username=username, password=password)

        if user is not None:
            # Login the user
            login(request, user)

            # Generate or get the authentication token
            token, created = Token.objects.get_or_create(user=user)

            # You can include additional user data in the response if needed
            user_serializer = UserSerializer(user)
            response_data ={
                'token': token.key,
                'user': user_serializer.data,
                'message': 'Login successful'
            }
            email1 = EmailMessage(
                'subject',
                'body',settings.EMAIL_HOST_USER,
                [user.email],
            # email.fail_silently = False 
            email1.send()
            )

            return Response(response_data)
        else:
            return Response({'error': 'Invalid credentials'})

    except Exception as e:
        return Response({'error': f'There is an error: {str(e)}'})
# @receiver(user_logged_in)
# def send_user_login_email(sender, request, user, **kwargs):
#     # Your email subject, message, and from email address
#     subject = 'User Login Notification'
#     message = f'Hello {user.username},\n\nYou have successfully logged in.'
#     from_email = 'kabhilan05@gmail.com'

#     # Send email
#     send_mail(subject, message, from_email, [user.email])
    

#Logout

@api_view(["POST"])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
@ratelimit(key='user', rate='5/m', block=True)
def user_logout(request):
    try:
        # Logout the user
        logout(request)

        # Delete the authentication token
        request.auth.delete()

        return Response({'message': 'Logout successful'})

    except Exception as e:
        return Response({'error': f'There is an error: {str(e)}'})