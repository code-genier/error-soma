import os
import jwt
import time
import hmac
import hashlib
import requests
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from dotenv import load_dotenv

app = FastAPI()

# Load environment variables from .env file
load_dotenv()

GITHUB_APP_ID = "278"
WEBHOOK_SECRET = "123"
PRIVATE_KEY_PATH = "pr-check-temp.2024-07-21.private-key.pem"

# Read private key
with open(PRIVATE_KEY_PATH, "r") as key_file:
    PRIVATE_KEY = key_file.read()


def generate_jwt(app_id, private_key):
    # Generate JWT for GitHub App authentication
    payload = {
        "iat": int(time.time()),
        "exp": int(time.time()) + (10 * 60),
        "iss": app_id,
    }
    return jwt.encode(payload, private_key, algorithm="RS256")


async def verify_signature(request: Request):
    signature = request.headers.get("X-Hub-Signature-256")
    if not signature:
        raise HTTPException(status_code=400, detail="Missing X-Hub-Signature-256 header")

    payload = await request.body()
    computed_signature = "sha256=" + hmac.new(WEBHOOK_SECRET.encode(), payload, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(computed_signature, signature):
        raise HTTPException(status_code=400, detail="Invalid signature")


async def post_comment(owner, repo, pr_number, comment, installation_id):
    # Generate JWT
    jwt_token = generate_jwt(GITHUB_APP_ID, PRIVATE_KEY)

    # Get installation access token
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Accept": "application/vnd.github+json",
    }
    response = requests.post(
        f"https://git.soma.salesforce.com/api/v3/app/installations/{installation_id}/access_tokens",
        headers=headers,
    )
    response.raise_for_status()
    access_token = response.json()["token"]

    # Post comment
    headers["Authorization"] = f"token {access_token}"
    comment_url = f"https://git.soma.salesforce.com/api/v3/repos/{owner}/{repo}/issues/{pr_number}/comments"
    response = requests.post(
        comment_url,
        headers=headers,
        json={"body": comment},
    )
    response.raise_for_status()


@app.post("/webhook")
async def handle_webhook(request: Request):
    await verify_signature(request)
    payload = await request.json()

    if payload["action"] in ["opened", "edited", "synchronize"]:
        pr_url = payload["pull_request"]["url"]
        pr_number = payload["pull_request"]["number"]
        installation_id = payload["installation"]["id"]
        owner = payload["repository"]["owner"]["login"]
        repo = payload["repository"]["name"]
        await post_comment(owner, repo, pr_number, f"Validating your PR...", installation_id)

    return JSONResponse({"message": "Comment posted"})


@app.get("/")
def read_root():
    return {"Hello": "World"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
