# python 3.9
import os
from huggingface_hub import hf_hub_download
import tensorflow as tf
from keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import load_model
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import base64
import uvicorn
import boto3
from botocore.exceptions import BotoCoreError, ClientError
from concurrent.futures import ThreadPoolExecutor
import asyncio
from datetime import datetime

load_dotenv()

class Payload(BaseModel):
    payload: str
    event_id: str
    request_created_at: str

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

app = FastAPI()

def load_model_detector():
    local_model_path = hf_hub_download(
        repo_id="noobpk/dga-detection",
        filename="model.h5"
    )
    return load_model(local_model_path)
    
model_detector = load_model_detector()

valid_characters = "$abcdefghijklmnopqrstuvwxyz0123456789-_."
tokens = {char: idx for idx, char in enumerate(valid_characters)}

def get_decoded_auth(authorization: str) -> str:
    try:
        if not authorization.startswith("Basic "):
            raise HTTPException(status_code=401, detail={"status": "error", "message": "Unauthorized", "error_code": 401})
        encoded_auth = authorization[len("Basic "):]
        decoded_auth = base64.b64decode(encoded_auth).decode()
        return decoded_auth
    except Exception:
        raise HTTPException(status_code=401, detail={"status": "error", "message": "Unauthorized", "error_code": 401})

@app.get("/api/v1/ws/services/dga-detection/ping")
def ping_info(authorization: str = Header(None)):
    decoded_auth = get_decoded_auth(authorization)
    if decoded_auth != f"ws:{AUTH_KEY}":
        raise HTTPException(status_code=401, detail={"status": "error", "message": "Unauthorized", "error_code": 401})
    return {
        "model": "noobpk/dga-detection",
        "max_input_length": "unlimit",
        "vector_size": "45",
        "param": "5612705",
        "model_build_at": "25-03-2025",
        "encoder": "pad_sequences",
        "author": "noobpk - lethanhphuc",
    }

@app.post("/api/v1/ws/services/dga-detection")
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

    # Convert domain to lowercase and encode it
    payload_encoded = [tokens[char] for char in payload_data.lower() if char in tokens]

    # Pad and truncate the sequence
    domain_encoded = pad_sequences([payload_encoded], maxlen=45, padding='post', truncating='post')

    def predict():
        return model_detector.predict(domain_encoded)

    def calculate_accuracy(prediction):
        return float(prediction[0][0] * 100)

    with ThreadPoolExecutor() as executor:
        prediction = executor.submit(predict).result()
        accuracy = executor.submit(calculate_accuracy, prediction).result()

   # Replace "WS_GATEWAY_SERVICE" with "WS_WEB_ATTACK_DETECTION" in event_id
    event_id = payload.event_id.replace("WS_GATEWAY_SERVICE", "WS_DGA_DETECTION")

    return JSONResponse(content={
        "status": "success",
        "message": "Request processed successfully",
        "data": {
            "threat_metrix": {
                "domain": payload_data,
                "class": 1 if prediction[0][0] > 0.9 else 0,
                "score": accuracy,
            }
        },
        "event_id": event_id,
        "request_created_at": payload.request_created_at,
        "request_processed_at": datetime.now().astimezone().isoformat()
    })

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5002)