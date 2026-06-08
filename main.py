import os
import secrets
from typing import List, Optional, Dict
from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
import pyschlage

class LockState(BaseModel):
    device_id: str
    name: str
    model_name: Optional[str] = None
    battery_level: Optional[int] = None
    is_locked: Optional[bool] = None
    is_jammed: Optional[bool] = None
    firmware_version: Optional[str] = None
    mac_address: Optional[str] = None

class AccessCodeBase(BaseModel):
    name: str
    code: str

class AccessCodeResponse(AccessCodeBase):
    access_code_id: Optional[str] = None

class LockLogResponse(BaseModel):
    created_at: Optional[str] = None
    message: Optional[str] = None
    access_code_id: Optional[str] = None

class TokenResponse(BaseModel):
    access_token: str
    token_type: str

app = FastAPI(
    title="Schlage Lock API",
    description="FastAPI wrapper for pyschlage with Bearer Token Authentication.",
    version="1.1.0"
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

_active_sessions: Dict[str, pyschlage.Schlage] = {}

API_SECRET = os.environ.get("API_SECRET")

@app.middleware("http")
async def check_api_secret(request: Request, call_next):
    if API_SECRET is None:
        return await call_next(request)
    if request.url.path == "/auth/token":
        return await call_next(request)
    if request.headers.get("X-API-Secret") != API_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")
    return await call_next(request)

def get_current_client(token: str = Depends(oauth2_scheme)) -> pyschlage.Schlage:
    client = _active_sessions.get(token)
    if not client:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return client

def get_lock_by_id(device_id: str, client: pyschlage.Schlage = Depends(get_current_client)):
    try:
        locks = client.locks()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch locks: {str(e)}")

    for lock in locks:
        if lock.device_id == device_id:
            return lock

    raise HTTPException(status_code=404, detail=f"Lock {device_id} not found")

@app.post("/auth/token", response_model=TokenResponse, tags=["Authentication"])
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    try:
        auth = pyschlage.Auth(form_data.username, form_data.password)
        client = pyschlage.Schlage(auth)
        client.locks()
        token = secrets.token_urlsafe(32)
        _active_sessions[token] = client
        return {"access_token": token, "token_type": "bearer"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect Schlage username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

@app.post("/auth/logout", tags=["Authentication"])
def logout(token: str = Depends(oauth2_scheme)):
    if token in _active_sessions:
        del _active_sessions[token]
    return {"status": "success", "message": "Successfully logged out"}

@app.get("/locks", response_model=List[LockState], tags=["Locks"])
def list_locks(client: pyschlage.Schlage = Depends(get_current_client)):
    try:
        locks = client.locks()
        return [
            LockState(
                device_id=lock.device_id,
                name=lock.name,
                model_name=getattr(lock, 'model_name', None),
                battery_level=getattr(lock, 'battery_level', None),
                is_locked=getattr(lock, 'is_locked', None),
                is_jammed=getattr(lock, 'is_jammed', None),
                firmware_version=getattr(lock, 'firmware_version', None),
                mac_address=getattr(lock, 'mac_address', None)
            ) for lock in locks
        ]
    except Exception as e:
         raise HTTPException(status_code=500, detail=str(e))

@app.get("/locks/{device_id}", response_model=LockState, tags=["Locks"])
def get_lock(lock = Depends(get_lock_by_id)):
    return LockState(
        device_id=lock.device_id,
        name=lock.name,
        model_name=getattr(lock, 'model_name', None),
        battery_level=getattr(lock, 'battery_level', None),
        is_locked=getattr(lock, 'is_locked', None),
        is_jammed=getattr(lock, 'is_jammed', None),
        firmware_version=getattr(lock, 'firmware_version', None),
        mac_address=getattr(lock, 'mac_address', None)
    )

@app.post("/locks/{device_id}/lock", response_model=Dict[str, str], tags=["Locks"])
def lock_door(lock = Depends(get_lock_by_id)):
    try:
        lock.lock()
        return {"status": "success", "message": "Door locked successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/locks/{device_id}/unlock", response_model=Dict[str, str], tags=["Locks"])
def unlock_door(lock = Depends(get_lock_by_id)):
    try:
        lock.unlock()
        return {"status": "success", "message": "Door unlocked successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/locks/{device_id}/logs", response_model=List[LockLogResponse], tags=["Logs"])
def get_logs(lock = Depends(get_lock_by_id)):
    try:
        logs = lock.logs()
        return [
            LockLogResponse(
                created_at=str(getattr(log, "created_at", "")),
                message=getattr(log, "message", ""),
                access_code_id=getattr(log, "access_code_id", None)
            ) for log in logs
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/locks/{device_id}/access_codes", response_model=List[AccessCodeResponse], tags=["Access Codes"])
def list_access_codes(lock = Depends(get_lock_by_id)):
    try:
        codes = lock.access_codes()
        return [
            AccessCodeResponse(
                access_code_id=getattr(code, 'access_code_id', None),
                name=code.name,
                code=code.code
            ) for code in codes
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/locks/{device_id}/access_codes", response_model=AccessCodeResponse, tags=["Access Codes"])
def create_access_code(access_code: AccessCodeBase, lock = Depends(get_lock_by_id)):
    try:
        new_code = pyschlage.AccessCode(name=access_code.name, code=access_code.code)
        lock.add_access_code(new_code)
        return AccessCodeResponse(
            access_code_id=getattr(new_code, 'access_code_id', None),
            name=new_code.name,
            code=new_code.code
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/locks/{device_id}/access_codes/{access_code_id}", response_model=Dict[str, str], tags=["Access Codes"])
def delete_access_code(access_code_id: str, lock = Depends(get_lock_by_id)):
    try:
        lock.delete_access_code(access_code_id)
        return {"status": "success", "message": f"Access code {access_code_id} deleted"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
