import psycopg2
import jwt
from fastapi import FastAPI, HTTPException
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


# Connect to postgres database
conn = psycopg2.connect(f"dbname={dbname} user={dbuser} password={dbpw} host={host} port={port}")
cur = conn.cursor()


# Constants
acc_tok_exp = timedelta(seconds=acc_exp_time)
ref_tok_exp = timedelta(hours=ref_exp_time)

class Tokens(BaseModel):
    accessToken: str
    refreshToken: str


# Routes
app = FastAPI()

@app.get("/login/{user_id}")
async def generate_tokens(user_id):
    access_token = jwt.encode(
        {
            "id": user_id,
            "exp": datetime.now(tz=timezone.utc) + acc_tok_exp
        },
        key,
        algorithm=alg
    )
    refresh_token = jwt.encode(
        {
            "id": user_id,
            "exp": datetime.now(tz=timezone.utc) + ref_tok_exp
        },
        key,
        algorithm=alg
    )
    return {
        "accessToken": access_token,
        "refreshToken": refresh_token
    }


@app.post("/validate")
async def verify_token(tokens: Tokens):
    try:
        decoded = jwt.decode(tokens.accessToken, key, algorithms=[alg])
    except jwt.exceptions.ExpiredSignatureError as e:
        raise HTTPException(status_code=401, detail=f"{e}")
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"{e}")
    return decoded


@app.post("/refresh")
async def refresh(tokens: Tokens):
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
        except Exception as e:
            raise HTTPException(status_code=401, detail="Refresh token invalid")
        finally:
            newTokens = await generate_tokens(decoded["id"])
            cur.execute("INSERT INTO revoked VALUES (%s, %s, %s)", (tokens.refreshToken,
                                                                    decoded["id"],
                                                                    decoded["exp"]))
            return newTokens
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"{e}")


@app.post("/logout")
async def revoke(tokens: Tokens):
    try:
        decoded = jwt.decode(tokens.accessToken, key, algorithms=[alg])
        try:
            decoded = jwt.decode(tokens.refreshToken, key, algorithms=[alg])
            cur.execute("INSERT INTO revoked VALUES (%s, %s, %s)", (tokens.refreshToken,
                                                                    decoded["id"],
                                                                    decoded["exp"]))
        except Exception as e:
            raise HTTPException(status_code=401, detail="Refresh token invalid")
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"{e}")

