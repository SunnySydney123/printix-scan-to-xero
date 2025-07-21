          📄 Azure Function: Printix → Xero PDF Uploader

This Azure Function app listens for HTTP requests from Printix workflows, downloads PDF documents, retrieves associated metadata, uploads them to Xero Files API, and sends a callback notification to Printix when processing is complete. Watch technical setup instructions here, https://youtu.be/YahDDO_azEg

          📦 Features
✅ Securely downloads PDF files from Printix URLs

✅ Authenticates with Xero using Client Credentials flow

✅ Streams PDFs directly to Xero Files API

✅ Retrieves Printix metadata (username, email, device info)

✅ Sends signed callbacks to Printix when done

✅ Dynamically names files using metadata and timestamps

✅ HMAC-SHA256 request signing for Printix API calls



            🖥️ Function Route

| Method     | Route              | Auth Level  |
| :--------- | :----------------- | :---------- |
| `GET/POST` | `/api/showrequest` | `Anonymous` |

📑 Expected Request JSON
{
  "documentUrl": "https://printix.example.com/api/...",
  "metadataUrl": "https://printix.example.com/api/...",
  "callbackUrl": "https://printix.example.com/api/..."
}

          🔐 #Required Environment Variables

| Name                 | Description                                   |
| :------------------- | :-------------------------------------------- |
| `PRINTIX_SECRET_KEY` | Base64-encoded secret for Printix API signing |
| `XERO_CLIENT_ID`     | Xero API Client ID                            |
| `XERO_CLIENT_SECRET` | Xero API Client Secret                        |


            📚 Dependencies

Listed in requirements.txt (ensure Azure Functions Python library is included):

azure-functions

requests

          📈 Flow Overview

Receives a JSON request from a Printix workflow.

Downloads the PDF document via the provided documentUrl.

Retrieves optional metadata (username, email, etc.).

Authenticates with Xero and obtains an access token + tenant ID.

Streams the PDF to Xero Files API.

Sends a signed callback to the provided callbackUrl.

Returns a plain text response summarizing the operation.

        🚀 Deployment

Set up your Azure Function App (Python v3.11+ recommended), don't choose flex consumption, choose the Consumption based plan for your Azure Function(second option)

Configure Application Settings in Azure Portal for the required environment variables.

Deploy this function app (via VS Code or Azure CLI)

Test using a POST request to /api/showrequest

      📄 Sample Response

Document processed successfully!

File name: JohnDoe-20250611-130523.pdf

Direct upload to Xero: Success

Xero File ID: 1234abcd-5678-efgh-ijkl-9012mnopqrst

Printix Callback: Success

Metadata Retrieved:

- userName: John Doe

- userEmail: john@example.com

- workflowName: Invoice Upload

  
      📖 Notes

Callback payloads contain a JSON body with an optional errorMessage.

All request signing follows Printix's HMAC-SHA256 spec.

Xero authentication uses the Client Credentials grant for file uploads.

Working files left in folder as txt file, in case anyone wants to build part of it, can look at other function_app.txt files.
