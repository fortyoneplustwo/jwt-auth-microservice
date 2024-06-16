import psycopg2
import jwt
from fastapi import FastAPI, HTTPException, Security, Depends
from fastapi.security.api_key import APIKeyHeader
from datetime import datetime, timedelta, timezone
from pydantic import BaseModel
from dotenv import load_dotenv
import os 

# Load environment variables
load_dotenv()

dbname = os.getenv('DB_NAME')
dbuser = os.getenv('DB_USER')
dbpw = os.getenv('DB_PW')
host = os.getenv('HOST')
port = os.getenv('PORT')
key = os.getenv('SECRET')
alg = os.getenv('ALGORITHM')
acc_exp_time = int(os.getenv('ACC_EXP'))
ref_exp_time = int(os.getenv('REF_EXP'))
valid_api_key = os.getenv('API_KEY')


# Connect to postgres database
conn = psycopg2.connect(f"dbname={dbname} user={dbuser} password={dbpw} host={host} port={port}")
cur = conn.cursor()


# Constants
acc_tok_exp = timedelta(seconds=acc_exp_time)
ref_tok_exp = timedelta(hours=ref_exp_time)

class Tokens(BaseModel):
    accessToken: str
    refreshToken: str

class User(BaseModel):
    id: int

# Helpers
def authorize_req(api_key_header: str = Security(APIKeyHeader(name="Authorization"))):
    if api_key_header.startswith("Bearer "):
        api_key = api_key_header[len("Bearer "):]
        return api_key == valid_api_key
    raise HTTPException(
        status_code=401,
        detail="Could not validate credentials",
    )


# Routes
app = FastAPI()

@app.post("/login")
async def generate_tokens(user: User, authorized: str = Depends(authorize_req)):
    if not authorized :
        raise HTTPException(status_code=401, detail="Unauthorized")
    access_token = jwt.encode(
        {
            "id": user.id,
            "exp": (datetime.now(tz=timezone.utc) + acc_tok_exp).timestamp()
        },
        key,
        algorithm=alg
    )
    refresh_token = jwt.encode(
        {
            "id": user.id,
            "exp": (datetime.now(tz=timezone.utc) + ref_tok_exp).timestamp()
        },
        key,
        algorithm=alg
    )
    return {
        "accessToken": access_token,
        "refreshToken": refresh_token
    }


@app.post("/validate")
async def verify_token(tokens: Tokens, authorized: str = Depends(authorize_req)):
    if not authorized :
        raise HTTPException(status_code=401, detail="Unauthorized")
        
    try:
        decoded = jwt.decode(tokens.accessToken, key, algorithms=[alg])
    except jwt.exceptions.ExpiredSignatureError as e:
        raise HTTPException(status_code=401, detail=f"{e}")
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"{e}")
    return decoded


@app.post("/refresh")
async def refresh(tokens: Tokens, authorized: str = Depends(authorize_req)):
    if not authorized :
        raise HTTPException(status_code=401, detail="Unauthorized")
    try: 
        decoded = jwt.decode(tokens.accessToken, key, algorithms=[alg])
        return tokens
    except jwt.exceptions.ExpiredSignatureError as e:
        decoded = jwt.decode(tokens.accessToken,
                             key, 
                             algorithms=["HS256"], 
                             options={"verify_signature": False})
        cur.execute("SELECT * FROM revoked WHERE token = %s AND id = %s", (tokens.refreshToken, decoded["id"],))
        if cur.fetchone() is not None:
            raise HTTPException(status_code=401, detail="Refresh token revoked")
        try:
            decoded = jwt.decode(tokens.refreshToken, key, algorithms=[alg])
            access_token = jwt.encode(
                {
                    "id": decoded["id"],
                    "exp": (datetime.now(tz=timezone.utc) + acc_tok_exp).timestamp()
                },
                key,
                algorithm=alg
            )
            refresh_token = jwt.encode(
                {
                    "id": decoded["id"],
                    "exp": (datetime.now(tz=timezone.utc) + ref_tok_exp).timestamp()
                },
                key,
                algorithm=alg
            )
            cur.execute("INSERT INTO revoked VALUES (%s, %s, %s)", (tokens.refreshToken,
                                                                    decoded["id"],
                                                                    decoded["exp"]))
            conn.commit()
            return {
                "accessToken": access_token,
                "refreshToken": refresh_token
            }
        except Exception as e:
            raise HTTPException(status_code=401, detail=f"{e}")
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"{e}")


@app.post("/logout")
async def revoke(tokens: Tokens, authorized: str = Depends(authorize_req)):
    if not authorized :
        raise HTTPException(status_code=401, detail="Unauthorized")
    try:
        decoded = jwt.decode(tokens.accessToken, key, algorithms=[alg])
        decoded = jwt.decode(tokens.refreshToken, key, algorithms=[alg])
        cur.execute("INSERT INTO revoked VALUES (%s, %s, %s)", (tokens.refreshToken,
                                                                decoded["id"],
                                                                decoded["exp"]))
        conn.commit()
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"{e}")

