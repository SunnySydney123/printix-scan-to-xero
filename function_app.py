import azure.functions as func
import logging
import requests
import base64
import hmac
import hashlib
import json
import time
import uuid
from urllib.parse import urlparse
import os
from datetime import datetime

app = func.FunctionApp()

def get_simple_filename(url: str, username: str = None) -> str:
    """Create a simple filename with username-date-time format"""
    try:
        # Get current timestamp for the filename
        now = datetime.now()
        timestamp = now.strftime("%Y%m%d-%H%M%S")
        
        # Create filename with username if available
        if username:
            # Sanitize username for filename (remove special chars)
            clean_username = ''.join(c for c in username if c.isalnum() or c in [' ', '_', '-'])
            clean_username = clean_username.replace(' ', '-')
            simple_filename = f"{clean_username}-{timestamp}.pdf"
        else:
            simple_filename = f"{timestamp}.pdf"
        
        return simple_filename
    except Exception as e:
        logging.error(f"Error creating filename: {str(e)}")
        # Return a default filename if something goes wrong
        return f"document-{datetime.now().strftime('%Y%m%d-%H%M%S')}.pdf"

def generate_printix_signature(secret_key, request_id, timestamp, method, request_path, request_body):
    """
    Generate HMAC-SHA-256 signature for Printix
    """
    try:
        # Create string to sign according to Printix documentation
        string_to_sign = f"{request_id}.{timestamp}.{method}.{request_path}.{request_body}"
        logging.info(f"String to sign: {string_to_sign}")
        
        # Decode the secret key from base64
        secret_key_bytes = base64.b64decode(secret_key)
        
        # Create the HMAC-SHA-256 signature
        signature = hmac.new(
            secret_key_bytes, 
            string_to_sign.encode('utf-8'), 
            hashlib.sha256
        ).digest()
        
        # Encode the signature as base64
        encoded_signature = base64.b64encode(signature).decode('utf-8')
        return encoded_signature
    except Exception as e:
        logging.error(f"Error generating Printix signature: {str(e)}")
        raise

def get_printix_metadata(metadata_url, metadata_fields=None):
    """
    Query metadata from Printix with proper authentication
    """
    if not metadata_fields:
        metadata_fields = ["userName", "userEmail", "deviceId", "workflowName"]
    
    logging.info(f"Querying Printix metadata from: {metadata_url}")
    
    # Build the complete URL with query parameters
    query_string = ",".join(metadata_fields)
    full_url = f"{metadata_url}{query_string}&format=object"
    logging.info(f"Full metadata URL: {full_url}")
    
    # Get the secret key from environment variables
    secret_key = os.environ.get('PRINTIX_SECRET_KEY')
    if not secret_key:
        logging.error("No Printix secret key found. Cannot query metadata.")
        return None
    
    # Generate request ID and timestamp for authentication
    request_id = str(uuid.uuid4())
    timestamp = str(int(time.time()))
    
    # Extract request path from URL
    parsed_url = urlparse(full_url)
    request_path = parsed_url.path
    if parsed_url.query:
        request_path += "?" + parsed_url.query
    
    # Generate signature for metadata request
    signature = generate_printix_signature(
        secret_key,
        request_id,
        timestamp,
        "get",
        request_path,
        ""  # Empty body for GET request
    )
    
    # Prepare headers
    headers = {
        "X-Printix-Request-Id": request_id,
        "X-Printix-Timestamp": timestamp,
        "X-Printix-Signature": signature
    }
    
    try:
        # Send GET request to Printix API
        response = requests.get(
            full_url,
            headers=headers
        )
        
        if response.status_code == 200:
            logging.info("Metadata query successful")
            return response.json()
        else:
            logging.error(f"Error querying metadata: HTTP {response.status_code}")
            logging.error(f"Response: {response.text}")
            return None
    except Exception as e:
        logging.error(f"Exception querying metadata: {str(e)}")
        return None

def get_xero_token_and_tenant_id():
    """
    Get an access token using Client Credentials grant and retrieve tenant ID
    """
    logging.info("Authenticating with Xero...")
    
    # Get credentials from environment variables
    client_id = os.environ.get("XERO_CLIENT_ID")
    client_secret = os.environ.get("XERO_CLIENT_SECRET")
    
    # Validate that credentials exist
    if not client_id or not client_secret:
        raise Exception("Xero credentials not found in environment variables. Please set XERO_CLIENT_ID and XERO_CLIENT_SECRET.")
    
    # Token endpoint
    token_url = "https://identity.xero.com/connect/token"
    
    # Create credentials string and encode it properly
    credentials = f"{client_id}:{client_secret}"
    encoded_credentials = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
    
    # Set headers and form data for token request
    headers = {
        "Authorization": f"Basic {encoded_credentials}",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    # Request scope for files API
    data = {
        "grant_type": "client_credentials",
        "scope": "files"
    }
    
    # Request the token
    response = requests.post(token_url, headers=headers, data=data)
    
    if response.status_code == 200:
        token_data = response.json()
        access_token = token_data["access_token"]
        logging.info("Authentication successful!")
        
        # Now get the tenant ID
        logging.info("Retrieving tenant ID...")
        connections_url = "https://api.xero.com/connections"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        
        conn_response = requests.get(connections_url, headers=headers)
        
        if conn_response.status_code == 200:
            connections = conn_response.json()
            if connections:
                # Get the tenant ID from the first connection
                tenant_id = connections[0]["tenantId"]
                logging.info(f"Found tenant ID: {tenant_id}")
                return {
                    "access_token": access_token,
                    "tenant_id": tenant_id
                }
            else:
                raise Exception("No connections found for this account")
        else:
            logging.error(f"Failed to get connections: {conn_response.status_code}")
            logging.error(f"Response: {conn_response.text}")
            raise Exception("Could not retrieve tenant ID")
    else:
        logging.error(f"Authentication failed: {response.status_code}")
        logging.error(f"Response: {response.text}")
        raise Exception("Authentication failed")

def upload_to_xero_from_url(access_token, tenant_id, document_url, file_name):
    """
    Stream file directly from Printix URL to Xero Files API
    """
    logging.info(f"Starting direct upload from Printix to Xero: {file_name}")
    
    # Download the file from Printix URL and stream to Xero
    try:
        # Start downloading from Printix
        logging.info(f"Downloading from Printix URL: {document_url}")
        printix_response = requests.get(document_url, stream=True)
        printix_response.raise_for_status()
        
        # Upload endpoint for Xero
        upload_url = "https://api.xero.com/files.xro/1.0/Files"
        
        # Set headers for Xero authentication
        headers = {
            "Authorization": f"Bearer {access_token}",
            "xero-tenant-id": tenant_id
        }
        
        # MIME type for PDF
        mime_type = "application/pdf"
        
        # Create multipart form data for file upload
        files = {
            'File': (file_name, printix_response.raw, mime_type)
        }
        
        data = {
            'Name': file_name,
            'Filename': file_name
        }
        
        logging.info("Uploading stream to Xero...")
        
        # Upload the file to Xero directly from the stream
        xero_response = requests.post(
            upload_url, 
            headers=headers,
            files=files,
            data=data
        )
        
        if xero_response.status_code in (200, 201):
            result = xero_response.json()
            logging.info(f"File uploaded successfully to Xero!")
            logging.info(f"File ID: {result.get('Id')}")
            logging.info(f"File Name: {result.get('Name')}")
            return result
        else:
            logging.error(f"Error uploading file to Xero: HTTP {xero_response.status_code}")
            logging.error(f"Response: {xero_response.text}")
            return None
    except requests.exceptions.RequestException as e:
        logging.error(f"Error streaming file to Xero: {str(e)}")
        return None

def send_printix_callback(callback_url, request_id=None, timestamp=None):
    """
    Send a callback to Printix to indicate that the processing is complete
    """
    logging.info(f"Sending callback to Printix: {callback_url}")

    # Generate a new request ID if not provided
    if not request_id:
        request_id = str(uuid.uuid4())
    
    # Generate a timestamp if not provided
    if not timestamp:
        timestamp = str(int(time.time()))
    
    # Create the callback payload - empty errorMessage means success
    callback_payload = {
        "errorMessage": None
    }
    
    # Convert payload to JSON string with no spaces
    request_body = json.dumps(callback_payload, separators=(',', ':'))
    
    # Extract request path from URL
    parsed_url = urlparse(callback_url)
    request_path = parsed_url.path
    if parsed_url.query:
        request_path += "?" + parsed_url.query
    
    # Get the secret key from environment variables
    secret_key = os.environ.get('PRINTIX_SECRET_KEY')
    if not secret_key:
        logging.error("No Printix secret key found. Cannot generate signature.")
        return False
    
    try:
        # Generate signature
        signature = generate_printix_signature(
            secret_key,
            request_id,
            timestamp,
            "post",
            request_path,
            request_body
        )
        
        # Prepare headers
        headers = {
            "X-Printix-Request-Id": request_id,
            "X-Printix-Timestamp": timestamp,
            "X-Printix-Signature": signature,
            "Content-Type": "application/json"
        }
        
        # Send the callback to Printix
        response = requests.post(
            callback_url,
            headers=headers,
            data=request_body
        )
        
        if response.status_code == 200:
            logging.info("Callback to Printix successful")
            return True
        else:
            logging.error(f"Error sending callback to Printix: HTTP {response.status_code}")
            logging.error(f"Response: {response.text}")
            return False
    except Exception as e:
        logging.error(f"Exception sending callback to Printix: {str(e)}")
        return False

@app.route(route="showrequest", auth_level=func.AuthLevel.ANONYMOUS)
def show_request(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Received a Printix request.")
    
    try:
        # Get request body as JSON
        try:
            request_json = req.get_json()
        except ValueError:
            return func.HttpResponse(
                "Invalid JSON in request body",
                status_code=400
            )

        # Extract document URL, metadata URL and callback URL from the request
        document_url = request_json.get('documentUrl')
        metadata_url = request_json.get('metadataUrl')
        callback_url = request_json.get('callbackUrl')
        
        if not document_url:
            return func.HttpResponse(
                "No document URL found in request",
                status_code=400
            )

        logging.info(f"Document URL received: {document_url}")
        logging.info(f"Metadata URL received: {metadata_url}")
        logging.info(f"Callback URL received: {callback_url}")

        # Query metadata to get username if possible
        username = None
        if metadata_url:
            metadata = get_printix_metadata(metadata_url)
            if metadata and 'userName' in metadata:
                username = metadata['userName']
                logging.info(f"Username found in metadata: {username}")
            
            # Log other interesting metadata fields
            if metadata:
                for field in ['userEmail', 'deviceId', 'deviceLocation', 'workflowName']:
                    if field in metadata:
                        logging.info(f"Metadata {field}: {metadata[field]}")

        # Create a filename with username if available
        file_name = get_simple_filename(document_url, username)
        logging.info(f"Generated filename: {file_name}")

        # Process the file directly from Printix to Xero
        try:
            # Get authentication token and tenant ID for Xero
            auth_data = get_xero_token_and_tenant_id()
            
            # Stream the document directly from Printix to Xero
            xero_result = upload_to_xero_from_url(
                auth_data["access_token"],
                auth_data["tenant_id"],
                document_url,
                file_name
            )
            
            xero_status = "Success" if xero_result else "Failed"
            xero_file_id = xero_result.get('Id', 'N/A') if xero_result else 'N/A'
            
        except Exception as xe:
            logging.error(f"Error in Xero upload process: {str(xe)}")
            xero_status = f"Failed: {str(xe)}"
            xero_file_id = "N/A"

        # Send callback to Printix if a callback URL was provided
        callback_status = "Not attempted"
        if callback_url:
            callback_success = send_printix_callback(callback_url)
            callback_status = "Success" if callback_success else "Failed"
        
        # Create success response message
        message = (
            f"Document processed successfully!\n"
            f"File name: {file_name}\n"
            f"Direct upload to Xero: {xero_status}\n"
            f"Xero File ID: {xero_file_id}\n"
            f"Printix Callback: {callback_status}\n"
        )
        
        # Add metadata info to response if available
        if metadata:
            message += "\nMetadata Retrieved:\n"
            for key, value in metadata.items():
                message += f"- {key}: {value}\n"

        # Return 200 OK to the original request
        return func.HttpResponse(
            message,
            mimetype="text/plain",
            status_code=200
        )

    except Exception as e:
        error_message = f"Error processing request: {str(e)}"
        logging.error(error_message)
        return func.HttpResponse(
            error_message,
            status_code=500
        )
