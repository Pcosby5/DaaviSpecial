import jwt
from rest_framework.views import APIView
from .serializers import CustomUserSerializer
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import AuthenticationFailed
from .models import CustomUser
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model

CustomUser = get_user_model()


# Create your views here.
class SignUpView(APIView):
    def post(self, request):
        serializer = CustomUserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CustomLoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        user = CustomUser.objects.filter(username=username).first()

        if user is None:
            raise AuthenticationFailed('User not found')

        if not user.check_password(password):
            raise AuthenticationFailed('Incorrect password')

        refresh = RefreshToken.for_user(user)
        access_token = refresh.access_token

        response = Response(status=status.HTTP_200_OK)
        response.set_cookie(
            key='access_token',
            value=str(access_token),
            httponly=True,
            secure=True,  # Ensure to set this to True in production
            samesite='Strict'
        )
        response.set_cookie(
            key='refresh_token',
            value=str(refresh),
            httponly=True,
            secure=True,  # Ensure to set this to True in production
            samesite='Strict'
        )
        response.data = {
            'message': 'Login successful',
        }

        return response


class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            refresh_token = request.COOKIES.get('refresh_token')
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()

            response = Response(status=status.HTTP_205_RESET_CONTENT)
            response.delete_cookie('access_token')
            response.delete_cookie('refresh_token')
            return response
        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST)


class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({
            'username': user.username,
            'email': user.email
        })

