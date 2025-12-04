from django.urls import path
from . import views

urlpatterns = [
    path('<str:patient_id>/dashboard/', views.patient_dashboard, name='patient-dashboard'),
]