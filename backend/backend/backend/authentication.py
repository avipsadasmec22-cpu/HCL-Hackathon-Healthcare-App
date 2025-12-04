# accounts/views.py
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status

from django.contrib.auth.models import User
from django.db import transaction

from rest_framework_simplejwt.tokens import RefreshToken

import bcrypt

from functools import wraps
from django.http import JsonResponse
from django.conf import settings
import jwt
from backend.patient_dashboard.services.mongo_client import get_db
#from .serializers import UserSerializer  # from previous code


def get_auth_collection():
    db = get_db()
    return db.get_collection('auth')


def require_jwt_match_patient(view_func):
    """
    Decorator expects header:
      Authorization: Bearer <token>
    Token must be signed with settings.JWT_SECRET and contain 'patient_id' or 'sub'
    that matches the patient_id passed in the view kwargs.
    """
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        auth = request.META.get('HTTP_AUTHORIZATION', '')
        if not auth.startswith('Bearer '):
            return JsonResponse({'detail': 'Authorization header required'}, status=401)
        token = auth.split(' ', 1)[1].strip()
        try:
            payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[getattr(settings, 'JWT_ALGORITHM', 'HS256')])
        except Exception as e:
            return JsonResponse({'detail': f'Invalid token: {str(e)}'}, status=401)

        patient_id = kwargs.get('patient_id') or kwargs.get('pk')
        token_patient = payload.get('patient_id') or payload.get('sub')
        if not patient_id or not token_patient or str(token_patient) != str(patient_id):
            return JsonResponse({'detail': 'Token does not match patient id'}, status=403)

        request.jwt_payload = payload
        return view_func(request, *args, **kwargs)
    return _wrapped



# class PatientProviderLoginView(APIView):
#     """
#     Login endpoint that accepts:
#     {
#       "role": "patient" or "provider",
#       "id": "<patient_id or provider_id>",
#       "password": "<plaintext password>"
#     }
#     Checks credentials against the mock MongoDB (mongomock), creates/gets a Django User,
#     and returns JWT tokens on success.
#     """

#     permission_classes = [AllowAny]

#     def post(self, request):
#         data = request.data
#         role = data.get("role", "").lower()
#         id_value = data.get("id")
#         password = data.get("password")

#         if not role or not id_value or not password:
#             return Response(
#                 {"detail": "role, id and password are required."},
#                 status=status.HTTP_400_BAD_REQUEST,
#             )

#         if role not in ("patient", "provider"):
#             return Response(
#                 {"detail": "role must be 'patient' or 'provider'."},
#                 status=status.HTTP_400_BAD_REQUEST,
#             )

#         coll = (
#             get_patients_collection()
#             if role == "patient"
#             else get_providers_collection()
#         )
#         query_field = "patient_id" if role == "patient" else "provider_id"
#         doc = coll.find_one({query_field: id_value})

#         if not doc:
#             return Response(
#                 {"detail": "Invalid id or password."},
#                 status=status.HTTP_401_UNAUTHORIZED,
#             )

#         stored_hash = doc.get("password_hash")
#         if not stored_hash:
#             return Response(
#                 {"detail": "Password not set for this user in DB."},
#                 status=status.HTTP_401_UNAUTHORIZED,
#             )

#         # stored_hash is bytes (bcrypt hash)
#         if isinstance(stored_hash, str):
#             # sometimes mongomock stores bytes as str; ensure bytes
#             stored_hash = stored_hash.encode("utf-8")

#         if not bcrypt.checkpw(password.encode("utf-8"), stored_hash):
#             return Response(
#                 {"detail": "Invalid id or password."},
#                 status=status.HTTP_401_UNAUTHORIZED,
#             )

#         # At this point authentication against mock MongoDB succeeded.
#         # Create or get a corresponding Django User so we can issue tokens.
#         # We use a deterministic username to avoid duplicates.
#         django_username = f"{role}_{id_value}"

#         # Use transaction.atomic to avoid race conditions on user creation
#         with transaction.atomic():
#             user, created = User.objects.get_or_create(
#                 username=django_username,
#                 defaults={
#                     "first_name": doc.get("name", ""),
#                     "email": doc.get("email", ""),
#                 },
#             )
#             # Optionally, keep a flag or set_unusable_password
#             if created:
#                 user.set_unusable_password()
#                 user.save()

#         # Issue tokens using SimpleJWT
#         refresh = RefreshToken.for_user(user)
#         access_token = str(refresh.access_token)
#         refresh_token = str(refresh)

#         # Build response payload
#         user_data = UserSerializer(user).data
#         resp = {
#             "access": access_token,
#             "refresh": refresh_token,
#             "user": user_data,
#             "role": role,
#             "id": id_value,
#         }
#         return Response(resp, status=status.HTTP_200_OK)
