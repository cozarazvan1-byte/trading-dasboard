from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.requests import Request
from sqlalchemy import create_engine, Column, Integer, String, Float, ForeignKey
from sqlalchemy.orm import sessionmaker, Session, relationship, declarative_base
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional

# --- 1. CONFIGURĂRI DE SECURITATE ---
SECRET_KEY = "cheia-ta-secreta-foarte-lunga-si-sigura" # În producție se ține ascunsă
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 # Sesiunea expiră după o oră

# Unelte pentru criptare parole
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- 2. BAZA DE DATE ---
DATABASE_URL = "sqlite:///./trading.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- 3. TABELELE (Database Models) ---
class UserDB(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    
    # Relație: Un user are mai multe trade-uri
    trades = relationship("TradeDB", back_populates="owner")

class TradeDB(Base):
    __tablename__ = "trades"
    id = Column(Integer, primary_key=True, index=True)
    date = Column(String)
    pair = Column(String)
    direction = Column(String)
    risk = Column(String)
    rr = Column(String)
    pl = Column(Float)
    obs = Column(String)
    link = Column(String)
    
    # Legătura cu User-ul (Foreign Key)
    owner_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("UserDB", back_populates="trades")

Base.metadata.create_all(bind=engine)

# --- 4. SCHEME DE DATE (Ce primim de la Frontend) ---
class UserLogin(BaseModel):
    username: str
    password: str

class TradeSchema(BaseModel):
    date: str
    pair: str
    direction: str
    risk: str
    rr: str
    pl: float
    obs: str
    link: str

# --- 5. FUNCȚII DE SECURITATE (AJUTĂTOARE) ---
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# --- 6. SERVERUL ---
app = FastAPI()
templates = Jinja2Templates(directory="templates")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- GARDIANUL (Verifică dacă ai Token valid) ---
async def get_current_user(request: Request, db: Session = Depends(get_db)):
    # Luăm token-ul din Header-ul cererii
    token = request.headers.get("Authorization")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        # Token-ul vine ca "Bearer xxxx...", luăm doar partea a doua
        token = token.split(" ")[1] 
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401)
    except Exception:
        raise HTTPException(status_code=401, detail="Token invalid")
    
    user = db.query(UserDB).filter(UserDB.username == username).first()
    if user is None:
        raise HTTPException(status_code=401)
    return user

# --- RUTELE (API) ---

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# 1. ÎNREGISTRARE
@app.post("/api/register")
async def register(user: UserLogin, db: Session = Depends(get_db)):
    # Verificăm dacă există deja
    existing_user = db.query(UserDB).filter(UserDB.username == user.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
    
    # Creăm userul cu parola criptată
    hashed_pw = get_password_hash(user.password)
    new_user = UserDB(username=user.username, hashed_password=hashed_pw)
    db.add(new_user)
    db.commit()
    return {"msg": "User created successfully"}

# 2. LOGIN (Generează Token)
@app.post("/api/login")
async def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(UserDB).filter(UserDB.username == user.username).first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    
    # Generăm permisul de trecere
    access_token = create_access_token(data={"sub": db_user.username})
    return {"access_token": access_token, "token_type": "bearer"}

# 3. ADAUGĂ TRADE (Doar pentru userul logat)
@app.post("/api/trades/")
async def create_trade(trade: TradeSchema, db: Session = Depends(get_db), current_user: UserDB = Depends(get_current_user)):
    # AICI ESTE SECRETUL: Legăm trade-ul de ID-ul userului curent (current_user.id)
    db_trade = TradeDB(**trade.dict(), owner_id=current_user.id)
    db.add(db_trade)
    db.commit()
    return {"status": "success"}

# 4. CITEȘTE TRADE-URI (Doar ale mele)
@app.get("/api/trades/")
async def read_trades(db: Session = Depends(get_db), current_user: UserDB = Depends(get_current_user)):
    # Filtrăm: Dă-mi doar trade-urile unde owner_id este EGAL cu id-ul meu
    trades = db.query(TradeDB).filter(TradeDB.owner_id == current_user.id).all()
    return trades

# 5. ȘTERGE TRADE
@app.delete("/api/trades/{trade_id}")
async def delete_trade(trade_id: int, db: Session = Depends(get_db), current_user: UserDB = Depends(get_current_user)):
    # Verificăm să ștergem doar trade-ul nostru
    trade = db.query(TradeDB).filter(TradeDB.id == trade_id, TradeDB.owner_id == current_user.id).first()
    if trade:
        db.delete(trade)
        db.commit()
    return {"status": "deleted"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)