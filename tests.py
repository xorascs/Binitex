import pytest
from fastapi.testclient import TestClient
from binitex import app  # Import the FastAPI app

client = TestClient(app)

headers = {"Accept": "application/json", "Content-Type": "application/json"}

def test_login():
    response = client.post("/login", headers=headers, json={"email": "123@example.com", "password": "123"})
    assert response.status_code == 200  # Expect HTTP 200 OK
    assert "access_token" in response.json()  # Check if the response contains an access token

def test_register():
    response = client.post("/register", headers=headers, json={"email": "1234@example.com", "password": "1234@example.com"})
    assert response.status_code == 200  # Expect HTTP 201 Created

def test_public_data():
    response = client.get("/public-data", headers=headers)
    assert response.status_code == 200  # Expect HTTP 200 OK

def test_private_data():
    # First, log in and retrieve the token
    login_response = client.post("/login", json={"email": "123@example.com", "password": "123"})
    access_token = login_response.json()["access_token"]
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    }
    
    # Test private data with valid authorization
    response = client.get("/private-data", headers=headers)
    assert response.status_code == 200  # Expect HTTP 200 OK