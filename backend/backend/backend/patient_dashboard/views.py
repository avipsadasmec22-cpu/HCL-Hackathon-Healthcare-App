from django.http import JsonResponse
from backend.patient_dashboard.services.mongo_client import get_db
from backend.authentication import require_jwt_match_patient

@require_jwt_match_patient
def patient_dashboard(request, patient_id):
    """
    GET /patient/<patient_id>/dashboard/
    Response: { patient_id, wellness_goals: [...], preventive_care: [...], health_tip: "..." }
    """
    db = get_db()
    # adjust collection name to your Mongo schema
    patients = db.get_collection('patients')
    doc = patients.find_one({'patient_id': str(patient_id)})
    if not doc:
        return JsonResponse({'detail': 'Patient not found'}, status=404)

    # expected structure in Mongo: doc['wellness_goals'], doc['preventive_care']
    resp = {
        'patient_id': doc.get('patient_id'),
        'wellness_goals': doc.get('wellness_goals', []),
        'preventive_care': doc.get('preventive_care', []),
        'health_tip': doc.get('health_tip', ''),
    }
    return JsonResponse(resp, status=200, safe=False)