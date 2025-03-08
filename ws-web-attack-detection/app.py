import base64
import html
import json
import os
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from hashlib import sha256

from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sentence_transformers import SentenceTransformer
from keras.models import load_model
import uvicorn
import boto3
from botocore.exceptions import BotoCoreError, ClientError
import asyncio

class Payload(BaseModel):
    payload: str
    event_id: str
    request_created_at: str

load_dotenv()

AWS_KMS_ENABLE = os.getenv("AWS_KMS_ENABLE", "false").lower() == "true"

if AWS_KMS_ENABLE:
    try:
        kms_client = boto3.client('kms', region_name=os.getenv("AWS_REGION"))
        encrypted_api_key = os.getenv("API_KEY")
        decrypted_api_key = kms_client.decrypt(CiphertextBlob=base64.b64decode(encrypted_api_key))
        AUTH_KEY = decrypted_api_key['Plaintext'].decode('utf-8')
    except (BotoCoreError, ClientError) as e:
        raise Exception(f"Failed to retrieve API key from AWS KMS: {str(e)}")
else:
    AUTH_KEY = os.getenv("API_KEY")

whale_sentinel_model = load_model(os.getenv("WS_MODEL"))

app = FastAPI()

def load_encoder():
    model_name_or_path = os.environ.get("model_name_or_path", "sentence-transformers/all-MiniLM-L6-v2")
    return SentenceTransformer(model_name_or_path)

encoder = load_encoder()

def ws_decoder(_string: str) -> str:
    string = _string.replace(r"\%", "%").replace(r"\\", "").replace(r"<br/>", "")
    string = string.encode().decode("unicode_escape")
    string = urllib.parse.unquote(string)
    string = html.unescape(string)
    base64_pattern = r"( |,|;)base64,([A-Za-z0-9+/]*={0,2})"
    match = re.search(base64_pattern, string)
    if match:
        encoded_string = match.group(2)
        try:
            decoded_string = base64.b64decode(encoded_string).decode()
            string = string.replace(encoded_string, decoded_string)
        except:
            pass
    return string


def get_decoded_auth(authorization: str) -> str:
    try:
        if not authorization.startswith("Basic "):
            raise HTTPException(status_code=401, detail={"status": "error", "message": "Unauthorized", "error_code": 401})
        encoded_auth = authorization[len("Basic "):]
        decoded_auth = base64.b64decode(encoded_auth).decode()
        return decoded_auth
    except Exception:
        raise HTTPException(status_code=401, detail={"status": "error", "message": "Unauthorized", "error_code": 401})

@app.get("/api/v1/ws/services/web-attack-detection/ping")
def ping_info(authorization: str = Header(None)):
    decoded_auth = get_decoded_auth(authorization)
    if decoded_auth != f"ws:{AUTH_KEY}":
        raise HTTPException(status_code=401, detail={"status": "error", "message": "Unauthorized", "error_code": 401})
    return {
        "model": "Whale-Sentinel-Web-Attack-Detection",
        "sample": "592479",
        "max_input_length": "unlimit",
        "vector_size": "384",
        "param": "2536417",
        "model_build_at": "11-11-2023",
        "encoder": "sentence-transformers/all-MiniLM-L6-v2",
        "author": "noobpk - lethanhphuc",
    }

@app.post("/api/v1/ws/services/web-attack-detection")
async def detection(payload: Payload, authorization: str = Header(None)):
    try:
        # Enforce a 30-second timeout for the entire function
        result = await asyncio.wait_for(process_detection(payload, authorization), timeout=30.0)
        return result
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail={"status": "error", "message": "Request timed out", "error_code": 504})
    
async def process_detection(payload: Payload, authorization: str):
    decoded_auth = get_decoded_auth(authorization)
    if decoded_auth != f"ws:{AUTH_KEY}":
        raise HTTPException(status_code=401, detail={"status": "error", "message": "Unauthorized", "error_code": 401})
    
    payload_data = payload.payload
    decode_payload = ws_decoder(payload_data)
    embeddings = encoder.encode(decode_payload).reshape((1, 384))
    
    def predict():
        return whale_sentinel_model.predict(embeddings)

    def calculate_accuracy(prediction):
        return float(prediction[0][0] * 100)

    with ThreadPoolExecutor() as executor:
        prediction = executor.submit(predict).result()
        accuracy = executor.submit(calculate_accuracy, prediction).result()

   # Replace "WS_GATEWAY_SERVICE" with "WS_WEB_ATTACK_DETECTION" in event_id
    event_id = payload.event_id.replace("WS_GATEWAY_SERVICE", "WS_WEB_ATTACK_DETECTION")

    return JSONResponse(content={
        "status": "success",
        "message": "Request processed successfully",
        "data": {
            "threat_metrix": {
                "origin_payload": payload_data,
                "decode_payload": decode_payload,
                "score": accuracy,
            }
        },
        "event_id": event_id,
        "request_created_at": payload.request_created_at,
        "request_processed_at": datetime.now().astimezone().isoformat()
    })

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5001)