# HCL-Hackathon-Healthcare-App
# Project Overview

## Pages

The project has the following pages:
- Auth page
- Patient Dashboard (one at a time, depending upon auth) 
- Healthcare provider dashboard (one at a time, depending upon auth) 
- Profile page
- Healthcare information page

---

## Things in each page:

### Auth/Signup: -> connected to auth endpoints
- Id, password
- Profile picture (optional)
- Patient/Provider Selection
- Sign in button
- Consent

### Patient Dashboard: -> patient_dashboard endpoint
- Wellness goals which will include buttons to update progress
- Preventive care reminders
- Health tip

### Healthcare provider dashboard: -> provider_endpoint
- Patient drop down -> patient_endpoint
- Goal details
- Checkup details
- Change goals and add checkups
- Patient other details from profile

### Profile Page: -> patient_profile endpoint
- Allergies
- Medications
- Blood group
- Chronic illnesses
- Previous surgeries etc.

### Healthcare information page: info_endpoint
- Data pulled from backend and directly presented


## Tech Stack

| Layer | Technology |
|-------|------------|
| **Frontend** | React |
| **Backend** | Django REST framework |
| **DB** | MongoDB |

---

## Frontend Components

- Login & Signup Form
- Nav Bar
- General Health info Button
- Dashboard Cards → Goal & Patient
- General Healthcare info cards → (Reactbits)
- Patient dropdown 
- Patient Reminder/ Provider Reminder setter
- Provider Goal Setter
- Profile general info form

---

## Backend Design

### API Endpoints

| Endpoint | Database Connection |
|----------|---------------------|
| `/patient_dashboard/{patient_id}` | dashboard db |
| `/patient_profile/{patient_id}` | patient profile db |
| `/provider/{provider_id}` | provider db |
| `/login` | auth db |
| `/signup` | auth and patient/provider db |
| `/info` | info db |

---

## DB Collections

- Patient profile
- Patient Dashboard
- Provider dashboard
- Auth details

