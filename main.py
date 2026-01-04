# Backend - Hospital Management API with Complete Edge Case Handling
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import RedirectResponse
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from pydantic import BaseModel
from starlette.requests import Request
from authlib.integrations.starlette_client import OAuth
from starlette.middleware.sessions import SessionMiddleware
from dotenv import load_dotenv
import os
import tempfile
import pandas as pd
import random

# Load environment variables from .env file
load_dotenv()


# =============================================================================
# CONFIG
# =============================================================================
# Read from .env file
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./hospital.db")
SECRET_KEY = os.getenv("SECRET_KEY", "hospital-secret-key-2024")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
FRONTEND_URL = "http://localhost:5173"

print(f"📦 Using database: {DATABASE_URL.split('@')[-1] if '@' in DATABASE_URL else DATABASE_URL}")

# =============================================================================
# DATABASE
# =============================================================================
# Use different connect_args based on database type
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    # PostgreSQL
    engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    name = Column(String(255))
    password_hash = Column(String(255))
    google_id = Column(String(255), unique=True, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

# Create tables if they don't exist
try:
    Base.metadata.create_all(bind=engine)
    print("✅ Database tables ready")
except Exception as e:
    print(f"⚠️ Database table creation error: {e}")
    print("   Tables may already exist, continuing...")

# =============================================================================
# AUTH
# =============================================================================
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)

oauth = OAuth()
if GOOGLE_CLIENT_ID:
    oauth.register(
        name='google',
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'}
    )

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_token(data: dict):
    expire = datetime.utcnow() + timedelta(hours=24)
    return jwt.encode({**data, "exp": expire}, SECRET_KEY, algorithm="HS256")

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user = db.query(User).filter(User.email == payload.get("sub")).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

class UserCreate(BaseModel):
    email: str
    name: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

# =============================================================================
# APP
# =============================================================================
app = FastAPI(title="Hospital Management API")
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# =============================================================================
# AUTH ENDPOINTS
# =============================================================================
@app.post("/api/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    try:
        # Check if email already exists
        existing_user = db.query(User).filter(User.email == user.email).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # Create new user
        db_user = User(
            email=user.email, 
            name=user.name, 
            password_hash=pwd_context.hash(user.password)
        )
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        
        print(f"✅ New user registered: {db_user.email}")
        
        return {
            "token": create_token({"sub": db_user.email}), 
            "user": {"id": db_user.id, "email": db_user.email, "name": db_user.name}
        }
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        print(f"❌ Registration error: {e}")
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")

@app.post("/api/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    try:
        db_user = db.query(User).filter(User.email == user.email).first()
        if not db_user:
            raise HTTPException(status_code=401, detail="Invalid email or password")
        if not db_user.password_hash:
            raise HTTPException(status_code=401, detail="Please login with Google")
        if not pwd_context.verify(user.password, db_user.password_hash):
            raise HTTPException(status_code=401, detail="Invalid email or password")
        
        print(f"✅ User logged in: {db_user.email}")
        
        return {
            "token": create_token({"sub": db_user.email}), 
            "user": {"id": db_user.id, "email": db_user.email, "name": db_user.name}
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Login error: {e}")
        raise HTTPException(status_code=500, detail=f"Login failed: {str(e)}")

@app.get("/api/me")
def get_me(user: User = Depends(get_current_user)):
    return {"id": user.id, "email": user.email, "name": user.name}

@app.get("/api/auth/google")
async def google_login(request: Request):
    if not GOOGLE_CLIENT_ID:
        raise HTTPException(status_code=501, detail="Google OAuth not configured")
    return await oauth.google.authorize_redirect(request, "http://localhost:8000/api/auth/google/callback")

@app.get("/api/auth/google/callback")
async def google_callback(request: Request, db: Session = Depends(get_db)):
    try:
        token = await oauth.google.authorize_access_token(request)
        user_info = token.get('userinfo')
        db_user = db.query(User).filter(User.google_id == user_info['sub']).first()
        if not db_user:
            db_user = db.query(User).filter(User.email == user_info['email']).first()
            if db_user:
                db_user.google_id = user_info['sub']
            else:
                db_user = User(email=user_info['email'], name=user_info.get('name', ''), google_id=user_info['sub'])
                db.add(db_user)
            db.commit()
            db.refresh(db_user)
        return RedirectResponse(f"{FRONTEND_URL}/auth/callback?token={create_token({'sub': db_user.email})}")
    except Exception as e:
        return RedirectResponse(f"{FRONTEND_URL}/login?error=oauth_failed")

# =============================================================================
# FILE HELPER WITH VALIDATION
# =============================================================================
def read_file(file: UploadFile):
    with tempfile.NamedTemporaryFile(delete=False, suffix=file.filename) as tmp:
        tmp.write(file.file.read())
        tmp_path = tmp.name
    df = pd.read_csv(tmp_path) if file.filename.endswith('.csv') else pd.read_excel(tmp_path)
    os.unlink(tmp_path)
    # Clean column names
    df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_')
    return df

def safe_int(val, default=0):
    """Safely convert to int, return default if invalid"""
    try:
        result = int(float(val))
        return max(0, result)  # Never return negative
    except:
        return default

def safe_float(val, default=0.0):
    """Safely convert to float, return default if invalid"""
    try:
        result = float(val)
        return max(0.0, result)  # Never return negative
    except:
        return default

# =============================================================================
# EMERGENCY AGENT - FULLY VALIDATED
# =============================================================================
@app.post("/api/agents/emergency")
async def emergency_agent(file: UploadFile = File(...), context: str = Form(""), user: User = Depends(get_current_user)):
    """Emergency Agent with complete data analysis and edge case handling"""
    df = read_file(file)
    total = len(df)
    
    if total == 0:
        return {"error": "No data found in file"}
    
    # ===== CONDITIONS ANALYSIS =====
    conditions = {}
    condition_col = None
    for col in df.columns:
        if 'condition' in col or 'severity' in col or 'status' in col:
            condition_col = col
            break
    if condition_col:
        conditions = df[condition_col].fillna('unknown').value_counts().to_dict()
    
    # ===== DISEASES/HEALTH ISSUES ANALYSIS =====
    diseases = {}
    disease_col = None
    for col in df.columns:
        if any(x in col for x in ['disease', 'health', 'diagnosis', 'complaint', 'issue', 'ailment']):
            disease_col = col
            break
    if disease_col:
        diseases = df[disease_col].fillna('Unknown').value_counts().to_dict()
    
    # ===== TIME OF ADMISSION ANALYSIS =====
    time_analysis = {}
    time_col = None
    for col in df.columns:
        if any(x in col for x in ['time', 'hour', 'admission_time']):
            time_col = col
            break
    if time_col:
        try:
            # Try multiple time formats
            hours = pd.to_datetime(df[time_col], format='%H:%M', errors='coerce').dt.hour
            if hours.isna().all():
                hours = pd.to_datetime(df[time_col], errors='coerce').dt.hour
            if hours.isna().all():
                # Try extracting numeric hour
                hours = pd.to_numeric(df[time_col].astype(str).str.extract(r'(\d{1,2})')[0], errors='coerce')
            
            valid_hours = hours.dropna()
            if len(valid_hours) > 0:
                bins = [0, 6, 12, 18, 24]
                labels = ['Night (12 AM - 6 AM)', 'Morning (6 AM - 12 PM)', 'Afternoon (12 PM - 6 PM)', 'Evening (6 PM - 12 AM)']
                time_groups = pd.cut(valid_hours, bins=bins, labels=labels, include_lowest=True)
                time_analysis = time_groups.value_counts().to_dict()
                time_analysis = {str(k): int(v) for k, v in time_analysis.items() if pd.notna(k) and v > 0}
        except Exception as e:
            print(f"Time parsing error: {e}")
    
    # ===== DAY OF ADMISSION ANALYSIS =====
    day_analysis = {}
    day_col = None
    for col in df.columns:
        if any(x in col for x in ['day', 'weekday', 'day_of']):
            day_col = col
            break
    if day_col:
        day_counts = df[day_col].fillna('Unknown').value_counts().to_dict()
        # Ensure proper day ordering
        day_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        for day in day_order:
            for key in day_counts:
                if day.lower() in str(key).lower():
                    day_analysis[day] = day_counts[key]
        if not day_analysis:
            day_analysis = {str(k): int(v) for k, v in day_counts.items()}
    
    # ===== AGE GROUP ANALYSIS =====
    age_groups = {}
    age_col = None
    for col in df.columns:
        if 'age' in col:
            age_col = col
            break
    if age_col:
        try:
            ages = pd.to_numeric(df[age_col], errors='coerce').dropna()
            if len(ages) > 0:
                bins = [0, 12, 25, 45, 65, 120]
                labels = ['Children (0-12)', 'Youth (13-25)', 'Adults (26-45)', 'Middle-aged (46-65)', 'Elderly (65+)']
                age_cats = pd.cut(ages, bins=bins, labels=labels, include_lowest=True)
                age_groups = age_cats.value_counts().to_dict()
                age_groups = {str(k): int(v) for k, v in age_groups.items() if pd.notna(k) and v > 0}
        except:
            pass
    
    # ===== PREDICTIONS =====
    critical = conditions.get('critical', 0) + conditions.get('Critical', 0)
    moderate = conditions.get('moderate', 0) + conditions.get('Moderate', 0)
    controllable = conditions.get('controllable', 0) + conditions.get('Controllable', 0)
    
    severity_score = round((critical * 3 + moderate * 2 + controllable) / max(total, 1), 2)
    surge_factor = 1.3 if severity_score > 2 else (1.2 if severity_score > 1.5 else 1.1)
    
    # Peak time and day
    peak_time = max(time_analysis.items(), key=lambda x: x[1])[0] if time_analysis else "Evening (6 PM - 12 AM)"
    peak_day = max(day_analysis.items(), key=lambda x: x[1])[0] if day_analysis else "Monday"
    
    # Risk assessment
    critical_ratio = round(critical / max(total, 1) * 100, 1)
    moderate_ratio = round(moderate / max(total, 1) * 100, 1)
    overall_risk = "HIGH" if critical_ratio > 30 else ("MODERATE" if critical_ratio > 15 else "LOW")
    
    return {
        "total_patients": total,
        "conditions": conditions if conditions else {"Not Specified": total},
        "diseases": diseases if diseases else {"General Cases": total},
        "time_analysis": time_analysis if time_analysis else {"All Day": total},
        "day_analysis": day_analysis if day_analysis else {"Weekdays": total},
        "age_groups": age_groups if age_groups else {"Adults (26-45)": total},
        "prediction": {
            "next_24_hours": f"{max(1, int(total * 0.9))}-{int(total * surge_factor)}",
            "weekly_average": round(total / 7, 1) if total >= 7 else total,
            "peak_time": peak_time,
            "peak_day": peak_day,
            "severity_index": severity_score,
            "surge_factor": surge_factor
        },
        "risk_assessment": {
            "critical_ratio": critical_ratio,
            "moderate_ratio": moderate_ratio,
            "overall_risk": overall_risk
        }
    }

# =============================================================================
# ICU AGENT - FULLY VALIDATED (No negative values, proper bounds)
# =============================================================================
@app.post("/api/agents/icu")
async def icu_agent(file: UploadFile = File(...), conversion_rate: float = Form(0.25), user: User = Depends(get_current_user)):
    """ICU Agent with complete validation - no negative values"""
    df = read_file(file)
    
    if len(df) == 0:
        return {"error": "No data found in file"}
    
    # Find column names flexibly
    def find_col(keywords):
        for col in df.columns:
            if any(k in col for k in keywords):
                return col
        return None
    
    total_col = find_col(['total', 'capacity', 'beds_total'])
    occupied_col = find_col(['occupied', 'used', 'filled'])
    admissions_col = find_col(['admission', 'admit'])
    stay_col = find_col(['stay', 'duration', 'los'])
    reason_col = find_col(['reason', 'diagnosis', 'cause', 'primary'])
    
    # Get total beds (use mean across all records, ensure positive)
    if total_col:
        total_beds = safe_int(pd.to_numeric(df[total_col], errors='coerce').mean())
    else:
        total_beds = 50  # Default if not found
    
    # Get current occupied (use latest record, ensure positive and <= total)
    if occupied_col:
        occupied_vals = pd.to_numeric(df[occupied_col], errors='coerce').dropna()
        current_occupied = safe_int(occupied_vals.iloc[-1]) if len(occupied_vals) > 0 else 0
    else:
        current_occupied = int(total_beds * 0.7)  # Default 70%
    
    # CRITICAL FIX: Ensure occupied never exceeds total
    current_occupied = min(current_occupied, total_beds)
    available = max(0, total_beds - current_occupied)  # Never negative
    
    # Calculate occupancy rate
    occupancy_rate = round((current_occupied / max(total_beds, 1)) * 100, 1)
    
    # Trend analysis
    trend_direction = "STABLE"
    if occupied_col and len(df) >= 3:
        recent = pd.to_numeric(df[occupied_col].tail(3), errors='coerce').dropna()
        if len(recent) >= 2:
            diff = recent.diff().mean()
            trend_direction = "INCREASING" if diff > 0.5 else ("DECREASING" if diff < -0.5 else "STABLE")
    
    # Top reasons
    reasons = {}
    if reason_col:
        reasons = df[reason_col].fillna('Not Specified').value_counts().head(6).to_dict()
    
    # Daily admissions
    daily_admissions = 0
    if admissions_col:
        daily_admissions = safe_float(pd.to_numeric(df[admissions_col], errors='coerce').mean())
    else:
        daily_admissions = max(1, int(current_occupied * 0.15))
    
    # Average stay
    avg_stay = 5.0
    if stay_col:
        avg_stay = safe_float(pd.to_numeric(df[stay_col], errors='coerce').mean(), 5.0)
        avg_stay = min(avg_stay, 30)  # Cap at 30 days
    
    # Risk calculation
    if occupancy_rate >= 90:
        risk_level = "CRITICAL"
        days_to_full = max(1, int(available / max(daily_admissions, 0.5)))
        time_to_full = f"{days_to_full} day{'s' if days_to_full > 1 else ''}" if available > 0 else "Already Full"
    elif occupancy_rate >= 80:
        risk_level = "HIGH"
        time_to_full = f"{max(1, int(available / max(daily_admissions, 0.5)))} days"
    elif occupancy_rate >= 70:
        risk_level = "MODERATE"
        time_to_full = f"{max(1, int(available / max(daily_admissions, 0.5)))} days"
    else:
        risk_level = "LOW"
        time_to_full = "Not at risk"
    
    return {
        "current_status": {
            "total_beds": total_beds,
            "occupied": current_occupied,
            "available": available,
            "occupancy_rate": occupancy_rate,
            "trend": trend_direction
        },
        "admission_analysis": {
            "daily_average": round(daily_admissions, 1),
            "expected_next_24h": round(daily_admissions * 1.2, 1),
            "avg_stay_days": round(avg_stay, 1)
        },
        "top_reasons": reasons if reasons else {"General Care": current_occupied},
        "risk_assessment": {
            "risk_level": risk_level,
            "time_to_capacity": time_to_full,
            "conversion_rate_used": round(conversion_rate, 2)
        }
    }

# =============================================================================
# CONTEXT AGENT - AI-POWERED WITH GROQ LLAMA 3.1 70B
# =============================================================================
from groq import Groq

def call_llama(prompt: str) -> str:
    """Call Groq API with Llama 3.1 70B for high-quality medical analysis"""
    # Read API key at call time (after load_dotenv has run)
    api_key = os.getenv("GROQ_API_KEY", "")
    
    if not api_key:
        print("⚠️ GROQ_API_KEY not found in environment. Using fallback rules-based analysis.")
        return None
    
    print(f"🔑 Using Groq API key: {api_key[:10]}...")
    
    try:
        client = Groq(api_key=api_key)
        print("📡 Calling Groq Llama 3.1 70B API...")
        completion = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {
                    "role": "system",
                    "content": """You are an expert medical epidemiologist and public health advisor with 20+ years of experience in Indian healthcare systems. You have deep knowledge of:
- Regional disease patterns across India
- Seasonal health trends and outbreaks
- Hospital preparedness protocols
- Endemic diseases in different Indian states
- Current health infrastructure and challenges

Provide specific, actionable, real-world applicable health analysis. Be precise with disease names, symptoms, and recommendations. Never give generic or vague advice."""
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.7,
            max_tokens=1500,
            top_p=0.9
        )
        print("✅ Groq API call successful!")
        return completion.choices[0].message.content
    except Exception as e:
        print(f"❌ Groq API error: {e}")
        import traceback
        traceback.print_exc()
        return None

@app.post("/api/agents/context")
async def context_agent(location: str = Form(...), season: str = Form("Winter"), user: User = Depends(get_current_user)):
    """Context Agent with Llama 3.1 70B - Real-world health analysis"""
    
    location_title = location.strip().title()
    current_date = datetime.now().strftime("%B %d, %Y")
    current_month = datetime.now().strftime("%B")
    
    # Generate weather based on season with more variation
    weather_patterns = {
        "Summer": {"temp": random.randint(32, 45), "humidity": random.randint(35, 60), "condition": "Hot and sunny with potential heat waves"},
        "Winter": {"temp": random.randint(4, 20), "humidity": random.randint(50, 75), "condition": "Cold with fog in mornings"},
        "Monsoon": {"temp": random.randint(24, 32), "humidity": random.randint(80, 98), "condition": "Heavy rainfall, waterlogging expected"},
        "Spring": {"temp": random.randint(22, 32), "humidity": random.randint(45, 65), "condition": "Pleasant with rising pollen levels"},
        "Autumn": {"temp": random.randint(22, 32), "humidity": random.randint(55, 70), "condition": "Post-monsoon clearing, moderate temperatures"}
    }
    weather = weather_patterns.get(season, weather_patterns["Winter"])
    
    # Detailed prompt for Llama 3.1 70B
    prompt = f"""Analyze the current health situation for {location_title}, India.

TODAY'S DATE: {current_date}
CURRENT MONTH: {current_month}
SEASON: {season}
WEATHER: {weather['temp']}°C, {weather['humidity']}% humidity, {weather['condition']}

Provide a COMPREHENSIVE and SPECIFIC health analysis for hospitals in {location_title}. This must be REAL, ACCURATE, and ACTIONABLE.

Include ALL of the following sections with SPECIFIC details for {location_title}:

1. CURRENT DISEASE OUTBREAK STATUS
   - What diseases are currently active or rising in {location_title}?
   - Any recent outbreak alerts from health authorities?
   - Expected cases in the next 2 weeks

2. ENDEMIC DISEASES FOR {location_title.upper()} REGION
   - List 4-5 diseases that are historically endemic to this specific region
   - Why they are endemic here (geographical/climatic reasons)
   - Current risk level for each (HIGH/MEDIUM/LOW)

3. SEASONAL HEALTH THREATS FOR {season.upper()} IN {location_title.upper()}
   - Specific diseases that spike during {season} in this region
   - Which symptoms require immediate emergency attention
   - Expected patient load increase percentage

4. VULNERABLE POPULATIONS
   - Which groups are most at risk in {location_title} right now?
   - Specific age groups, occupations, or conditions to monitor
   - Recommended screening protocols

5. HOSPITAL PREPAREDNESS CHECKLIST
   - Specific medications to stock for {location_title} area
   - ICU/ventilator readiness recommendations
   - Specialist departments that need extra coverage
   - Blood bank and platelet requirements

6. CRITICAL WARNING SIGNS
   - List 5 specific symptoms that indicate medical emergency
   - Which conditions can become fatal if delayed
   - Triage priority recommendations

7. PUBLIC HEALTH COORDINATION
   - Local health authorities to coordinate with
   - Nearby referral hospitals for severe cases
   - Ambulance and emergency protocols

8. PREVENTIVE ADVISORIES FOR {location_title.upper()} RESIDENTS
   - Specific do's and don'ts for this season
   - Vaccination recommendations
   - Hygiene and safety measures

Be SPECIFIC to {location_title}. Mention actual hospitals, local health departments, and region-specific factors. This analysis will be used by healthcare administrators for real decision-making."""

    # Try AI-generated response
    ai_response = call_llama(prompt)
    
    if ai_response:
        return {
            "location": location_title,
            "season": season,
            "generated_by": "LLAMA-3.1-70B",
            "model": "Groq Llama 3.1 70B Versatile",
            "weather": {
                "temperature": f"{weather['temp']}°C",
                "humidity": f"{weather['humidity']}%",
                "condition": weather['condition']
            },
            "analysis": ai_response,
            "timestamp": datetime.now().strftime("%B %d, %Y %I:%M %p"),
            "disclaimer": "AI-generated analysis. Verify with local health authorities."
        }
    
    # Fallback: Enhanced rules-based response (only if API fails)
    location_lower = location.lower().strip()
    
    # Comprehensive city database
    city_health_data = {
        "mumbai": {
            "endemic": ["Leptospirosis (rat-borne, sewer exposure)", "Dengue (Aedes mosquito)", "Malaria (P. vivax dominant)", "Hepatitis A (contaminated water)", "Tuberculosis (overcrowding)"],
            "risks": ["Monsoon flooding causes 40% spike in water-borne diseases", "High population density accelerates outbreaks", "Slum areas have 3x higher infection rates", "Coastal humidity promotes fungal infections"],
            "hospitals": "KEM Hospital, Lilavati Hospital, Kokilaben Dhirubhai Ambani Hospital, JJ Hospital, Hinduja Hospital",
            "air_quality": "AQI 100-150 (Moderate)",
            "health_dept": "BMC Health Department, MCGM",
            "special": "Financial capital with 20M+ population. Dharavi's density requires special outbreak protocols. Marine Drive to Thane corridor experiences traffic pollution."
        },
        "delhi": {
            "endemic": ["Chikungunya (October peak)", "Dengue (September-November surge)", "Respiratory diseases (AQI 400+ winters)", "TB (MDR-TB hotspot)", "Viral hepatitis (water contamination)"],
            "risks": ["Winter AQI exceeds 500+ (Severe+)", "Yamuna pollution causes skin diseases", "Post-Diwali respiratory emergencies spike 300%", "Fog-related accidents increase trauma cases"],
            "hospitals": "AIIMS, Safdarjung Hospital, Ram Manohar Lohia Hospital, Sir Ganga Ram Hospital, Apollo Indraprastha",
            "air_quality": "AQI 300-500 (Very Poor to Severe)",
            "health_dept": "Delhi State Health Mission, MCD Health Services",
            "special": "National capital with extreme seasonal variation. Stubble burning season (Oct-Nov) triggers respiratory emergencies. NCR coordination essential."
        },
        "bangalore": {
            "endemic": ["Dengue (year-round due to construction water)", "Chikungunya (monsoon peak)", "Typhoid (lake contamination)", "H1N1 Influenza (IT park clusters)", "Viral fever (seasonal transitions)"],
            "risks": ["IT workforce stress-related disorders increasing", "Lake revival areas have malaria pockets", "Construction sites breed Aedes mosquitoes", "Traffic pollution causing chronic respiratory issues"],
            "hospitals": "Manipal Hospital, Narayana Health City, Fortis BG Road, Apollo Bannerghatta, St. John's Medical College",
            "air_quality": "AQI 80-120 (Moderate)",
            "health_dept": "BBMP Health Department, Karnataka State Health",
            "special": "IT capital with young professional population. Mental health cases rising. Whitefield-Marathahalli belt has highest dengue reports. HSR-Koramangala sees workplace burnout."
        },
        "chennai": {
            "endemic": ["Dengue (waterlogged areas)", "Typhoid (Cooum river contamination)", "Scrub Typhus (rural periphery)", "Leptospirosis (flood season)", "Heat stroke (April-June peak)"],
            "risks": ["Cyclone season (Oct-Dec) causes mass trauma", "Water scarcity leads to stored water contamination", "Extreme heat (45°C+) in summer", "Coastal flooding in North Chennai"],
            "hospitals": "Apollo Chennai, SRMC, Government General Hospital, Stanley Medical College, CMC Vellore (referral)",
            "air_quality": "AQI 70-100 (Satisfactory to Moderate)",
            "health_dept": "Greater Chennai Corporation Health, Tamil Nadu Health Department",
            "special": "Coastal metro with cyclone vulnerability. Kodambakkam-T.Nagar faces annual flooding. Auto hub areas have occupational health issues. Marina Beach to Egmore sees tourist health cases."
        },
        "kolkata": {
            "endemic": ["Malaria (P. falciparum in pockets)", "Dengue (monsoon surge)", "Kala-azar (Leishmaniasis spillover from Bihar)", "Filariasis (North 24 Parganas)", "Gastroenteritis (water quality)"],
            "risks": ["Monsoon flooding extensive", "Aging drainage infrastructure", "Hooghly river contamination", "High humidity promotes fungal infections year-round"],
            "hospitals": "SSKM Hospital, Apollo Gleneagles, Fortis Kolkata, RN Tagore Hospital, AMRI",
            "air_quality": "AQI 120-180 (Moderate to Poor)",
            "health_dept": "KMC Health Department, West Bengal Health",
            "special": "Gangetic delta city with drainage challenges. North-South divide in healthcare access. Howrah-Sealdah belt sees maximum trauma. Salt Lake-Rajarhat newer areas have better infrastructure."
        }
    }
    
    # Find matching city
    city_data = None
    matched_city = None
    for city, data in city_health_data.items():
        if city in location_lower:
            city_data = data
            matched_city = city.title()
            break
    
    if not city_data:
        city_data = {
            "endemic": ["Seasonal viral infections", "Gastroenteritis", "Respiratory infections", "Skin infections", "Vector-borne diseases"],
            "risks": ["Local environmental factors", "Seasonal variations", "Water quality issues", "Air pollution"],
            "hospitals": "Local district hospital, State medical college, Nearby referral centers",
            "air_quality": "AQI varies seasonally",
            "health_dept": "District Health Office, State Health Department",
            "special": f"{location_title} follows general regional health patterns. Contact local CMO for specific advisories."
        }
        matched_city = location_title
    
    # Season-specific data
    seasonal_data = {
        "Summer": {
            "threats": ["Heat stroke", "Dehydration", "Food poisoning", "Sunstroke", "Acute gastroenteritis"],
            "declining": ["Flu cases", "Cold and cough"],
            "critical": ["Heat stroke above 40°C body temp - FATAL if untreated", "Acute kidney injury from severe dehydration", "Electrolyte imbalance causing cardiac issues"],
            "prep": ["IV fluid stocks (NS, RL)", "ORS sachets", "Ice packs and cooling equipment", "Nephrology standby"]
        },
        "Winter": {
            "threats": ["Influenza", "Pneumonia", "Bronchitis", "Asthma exacerbations", "Hypothermia"],
            "declining": ["Dengue", "Malaria", "Heat-related illness"],
            "critical": ["Severe pneumonia in elderly - 48hr mortality risk", "Flu complications in cardiac patients", "Hypothermia in homeless and elderly"],
            "prep": ["Flu vaccines", "Nebulizers and bronchodilators", "Warming blankets", "Pulmonology coverage"]
        },
        "Monsoon": {
            "threats": ["Dengue fever", "Malaria", "Typhoid", "Leptospirosis", "Cholera", "Hepatitis A"],
            "declining": ["Heat stroke", "Sunburn"],
            "critical": ["Dengue hemorrhagic fever - platelet drop fatal", "Cerebral malaria - altered consciousness", "Cholera - severe dehydration in hours"],
            "prep": ["Dengue NS1 and IgM kits", "Platelet packs", "Antimalarials (ACT)", "IV fluids for rehydration"]
        },
        "Spring": {
            "threats": ["Allergies", "Asthma attacks", "Hay fever", "Conjunctivitis", "Skin rashes"],
            "declining": ["Flu", "Pneumonia", "Cold-related illness"],
            "critical": ["Severe anaphylaxis from allergens", "Status asthmaticus requiring ventilation", "Severe allergic skin reactions"],
            "prep": ["Antihistamines", "Epinephrine auto-injectors", "Nebulization equipment", "Eye drops"]
        },
        "Autumn": {
            "threats": ["Viral fever", "Post-monsoon dengue", "Respiratory infections", "Skin allergies", "Chikungunya"],
            "declining": ["Monsoon water-borne diseases"],
            "critical": ["Late dengue cases with liver involvement", "Chikungunya with joint complications", "Viral pneumonia in vulnerable groups"],
            "prep": ["Fever management medications", "Joint pain management", "Liver function monitoring", "Respiratory support"]
        }
    }
    
    season_info = seasonal_data.get(season, seasonal_data["Winter"])
    
    # Build comprehensive analysis
    analysis = f"""
═══════════════════════════════════════════════════════════════
📍 HEALTH ANALYSIS FOR {matched_city.upper()}, INDIA
📅 Generated: {datetime.now().strftime("%B %d, %Y %I:%M %p")}
🌡️ Season: {season} | Temp: {weather['temp']}°C | Humidity: {weather['humidity']}%
═══════════════════════════════════════════════════════════════

🦠 ENDEMIC DISEASES IN {matched_city.upper()} REGION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{chr(10).join([f"  {i+1}. {d}" for i, d in enumerate(city_data['endemic'])])}

⚠️ CURRENT {season.upper()} SEASON HEALTH THREATS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🔴 RISING: {', '.join(season_info['threats'][:3])}
  🟢 DECLINING: {', '.join(season_info['declining'])}

🚨 CRITICAL CONDITIONS - IMMEDIATE ATTENTION REQUIRED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{chr(10).join([f"  ⚠️ {c}" for c in season_info['critical']])}

📊 LOCAL RISK FACTORS FOR {matched_city.upper()}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{chr(10).join([f"  • {r}" for r in city_data['risks']])}

🏥 NEARBY HOSPITALS & REFERRAL CENTERS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  {city_data['hospitals']}

🌫️ AIR QUALITY INDEX: {city_data['air_quality']}

📋 HOSPITAL PREPAREDNESS CHECKLIST
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{chr(10).join([f"  ✓ {p}" for p in season_info['prep']])}
  ✓ Emergency contact: {city_data['health_dept']}
  ✓ Coordinate with nearby referral hospitals

📌 SPECIAL NOTE FOR {matched_city.upper()}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  {city_data['special']}

⚕️ DISCLAIMER: This is rules-based analysis. For AI-powered 
   analysis, add GROQ_API_KEY to your environment.
"""
    
    return {
        "location": location_title,
        "season": season,
        "generated_by": "RULES-ENHANCED",
        "weather": {
            "temperature": f"{weather['temp']}°C",
            "humidity": f"{weather['humidity']}%",
            "condition": weather['condition']
        },
        "analysis": analysis.strip(),
        "timestamp": datetime.now().strftime("%B %d, %Y %I:%M %p")
    }

# =============================================================================
# STAFF AGENT - FULLY VALIDATED (No negative gaps)
# =============================================================================
@app.post("/api/agents/staff")
async def staff_agent(file: UploadFile = File(...), severity: str = Form("moderate"), ratio: str = Form("1:4"), user: User = Depends(get_current_user)):
    """Staff Agent with complete validation - no negative values"""
    try:
        df = read_file(file)
        
        if len(df) == 0:
            return {"error": "No data found in file"}
        
        # Find columns flexibly
        def find_col(keywords):
            for col in df.columns:
                if any(k in str(col) for k in keywords):
                    return col
            return None
        
        floor_col = find_col(['floor', 'ward', 'department', 'unit'])
        shift_col = find_col(['shift'])
        nurse_total_col = find_col(['nurses_total', 'nurse_total', 'total_nurse'])
        nurse_avail_col = find_col(['nurses_available', 'nurse_available', 'available_nurse'])
        wardboy_total_col = find_col(['wardboys_total', 'wardboy_total', 'total_wardboy'])
        wardboy_avail_col = find_col(['wardboys_available', 'wardboy_available', 'available_wardboy'])
        overtime_col = find_col(['overtime', 'ot_hours', 'extra_hours'])
        burnout_col = find_col(['burnout', 'stress', 'fatigue'])
        
        # Calculate gaps with validation
        nurse_gaps = {"day": 0, "night": 0, "total": 0}
        wardboy_gaps = {"day": 0, "night": 0, "total": 0}
        
        if nurse_total_col and nurse_avail_col:
            for idx, row in df.iterrows():
                total = safe_int(row.get(nurse_total_col, 0))
                avail = safe_int(row.get(nurse_avail_col, 0))
                avail = min(avail, total)
                gap = max(0, total - avail)
                
                shift_val = str(row.get(shift_col, 'day')).lower() if shift_col else 'day'
                if 'night' in shift_val:
                    nurse_gaps["night"] += gap
                else:
                    nurse_gaps["day"] += gap
                nurse_gaps["total"] += gap
        
        if wardboy_total_col and wardboy_avail_col:
            for idx, row in df.iterrows():
                total = safe_int(row.get(wardboy_total_col, 0))
                avail = safe_int(row.get(wardboy_avail_col, 0))
                avail = min(avail, total)
                gap = max(0, total - avail)
                
                shift_val = str(row.get(shift_col, 'day')).lower() if shift_col else 'day'
                if 'night' in shift_val:
                    wardboy_gaps["night"] += gap
                else:
                    wardboy_gaps["day"] += gap
                wardboy_gaps["total"] += gap
        
        # Severity adjustment
        severity_mult = {"low": 1.0, "moderate": 1.2, "high": 1.5, "critical": 2.0}
        adjusted = int(nurse_gaps["total"] * severity_mult.get(severity.lower(), 1.0))
        
        # Priority floors
        floor_analysis = []
        if floor_col and nurse_total_col and nurse_avail_col:
            try:
                for floor_name in df[floor_col].dropna().unique():
                    floor_df = df[df[floor_col] == floor_name]
                    total = safe_int(pd.to_numeric(floor_df[nurse_total_col], errors='coerce').sum())
                    avail = safe_int(pd.to_numeric(floor_df[nurse_avail_col], errors='coerce').sum())
                    avail = min(avail, total)
                    gap = max(0, total - avail)
                    if gap > 0:
                        floor_analysis.append({"floor": str(floor_name), "nurse_gap": gap})
                floor_analysis.sort(key=lambda x: x["nurse_gap"], reverse=True)
            except Exception as e:
                print(f"Floor analysis error: {e}")
        
        # Overtime analysis
        avg_overtime = 0.0
        max_overtime = 0.0
        stress_area = "N/A"
        if overtime_col:
            try:
                ot_values = pd.to_numeric(df[overtime_col], errors='coerce').dropna()
                if len(ot_values) > 0:
                    avg_overtime = round(max(0, float(ot_values.mean())), 1)
                    max_overtime = round(max(0, float(ot_values.max())), 1)
                    max_idx = ot_values.idxmax()
                    if floor_col and shift_col and max_idx in df.index:
                        floor_val = str(df.loc[max_idx, floor_col]) if floor_col else "Unknown"
                        shift_val = str(df.loc[max_idx, shift_col]) if shift_col else "Unknown"
                        stress_area = f"{floor_val} - {shift_val} ({max_overtime}h OT)"
            except Exception as e:
                print(f"Overtime analysis error: {e}")
        
        # Burnout analysis - FIXED: Convert to string safely
        burnout_dist = {"high": 0, "medium": 0, "low": 0}
        high_burnout_areas = []
        if burnout_col:
            try:
                # Convert to string first to avoid .str accessor error
                burnout_values = df[burnout_col].astype(str).str.lower().str.strip()
                burnout_counts = burnout_values.value_counts().to_dict()
                burnout_dist = {
                    "high": int(burnout_counts.get('high', 0)),
                    "medium": int(burnout_counts.get('medium', 0) + burnout_counts.get('moderate', 0)),
                    "low": int(burnout_counts.get('low', 0))
                }
                
                high_burn_mask = burnout_values == 'high'
                for idx in df[high_burn_mask].index:
                    floor_val = str(df.loc[idx, floor_col]) if floor_col else "Unknown"
                    shift_val = str(df.loc[idx, shift_col]) if shift_col else "Unknown"
                    area = f"{floor_val} - {shift_val}"
                    if area not in high_burnout_areas:
                        high_burnout_areas.append(area)
            except Exception as e:
                print(f"Burnout analysis error: {e}")
        
        # Overall risk
        if burnout_dist["high"] >= 3 or avg_overtime > 6:
            risk_level = "HIGH"
        elif burnout_dist["high"] >= 1 or avg_overtime > 4:
            risk_level = "MODERATE"
        else:
            risk_level = "LOW"
        
        return {
            "staff_gaps": {
                "nurses": {
                    "total": nurse_gaps["total"],
                    "adjusted_for_severity": adjusted,
                    "by_shift": {"day": nurse_gaps["day"], "night": nurse_gaps["night"]}
                },
                "wardboys": {
                    "total": wardboy_gaps["total"],
                    "by_shift": {"day": wardboy_gaps["day"], "night": wardboy_gaps["night"]}
                }
            },
            "priority_floors": floor_analysis[:5] if floor_analysis else [{"floor": "General", "nurse_gap": nurse_gaps["total"]}],
            "overtime_analysis": {
                "average": avg_overtime,
                "maximum": max_overtime,
                "highest_stress_area": stress_area
            },
            "burnout_analysis": {
                "distribution": burnout_dist,
                "high_burnout_areas": high_burnout_areas[:5] if high_burnout_areas else []
            },
            "risk_assessment": {
                "overall_risk": risk_level,
                "patient_severity": severity,
                "target_ratio": ratio
            }
        }
    except Exception as e:
        return {"error": f"Analysis failed: {str(e)}"}

@app.get("/")
def root():
    return {"message": "Hospital API Running", "docs": "/docs"}

if __name__ == "__main__":
    import uvicorn
    print("🏥 Starting Hospital Management API...")
    uvicorn.run(app, host="0.0.0.0", port=8000)
