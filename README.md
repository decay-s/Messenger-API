# Telegram Messenger API Documentation

## Authentication
Most methods require authentication via token.

### Base URL
```
https://decay1234.pythonanywhere.com/api/bot{token}/{method}
```

### Response Format
All responses return JSON with structure:
```json
{
    "ok": boolean,
    "result": object/array,
    "error_code": number,
    "description": string
}
```

## Quick Start

### 1. Sign Up
```bash
POST /api/bot/signup
{
    "username": "user123",
    "password": "password123",
    "first_name": "John",
    "last_name": "Doe"
}
```

### 2. Sign In
```bash
POST /api/bot/signin
{
    "username": "user123",
    "password": "password123"
}
```

### 3. Send Message
```bash
POST /api/bot{token}/sendMessage
{
    "chat_id": 1,
    "text": "Hello World!"
}
```

## Rate Limits
- 600 requests per minute per IP
- Retry-After header included in 429 responses
```

## 2. صفحه راهنمای نصب و اجرا (Installation Guide)

```markdown
# Installation and Setup Guide

## Prerequisites
- Python 3.8+
- SQLite3
- pip

## Installation Steps

### 1. Clone Repository
```bash
git clone <repository-url>
cd messenger-api
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Environment Variables
Create `.env` file:
```env
SECRET_KEY=your-secret-key-here
DATABASE_URL=sqlite:///messenger.db
DEBUG=False
```

### 4. Initialize Database
```bash
python main.py
# Database will be created automatically
```

### 5. Run Server
```bash
python main.py
# Server runs on http://localhost:5000
```

## Docker Deployment
```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY . .
RUN pip install -r requirements.txt

EXPOSE 5000
CMD ["python", "main.py"]
```

## Production Deployment
- Use Gunicorn for production
- Configure reverse proxy (Nginx)
- Set up SSL certificate
- Configure database backups
```

## 3. صفحه مثال‌های کاربردی (Examples)

```markdown
# API Usage Examples

## Python Client Example
```python
import requests

class TelegramClient:
    def __init__(self, token):
        self.base_url = "https://decay1234.pythonanywhere.com/api/bot"
        self.token = token
    
    def send_message(self, chat_id, text):
        url = f"{self.base_url}{self.token}/sendMessage"
        response = requests.post(url, json={
            "chat_id": chat_id,
            "text": text
        })
        return response.json()

# Usage
client = TelegramClient("your-token-here")
response = client.send_message(1, "Hello!")
```

## JavaScript Example
```javascript
class TelegramClient {
    constructor(token) {
        this.baseUrl = 'https://decay1234.pythonanywhere.com/api/bot';
        this.token = token;
    }

    async sendMessage(chatId, text) {
        const response = await fetch(`${this.baseUrl}${this.token}/sendMessage`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({chat_id: chatId, text})
        });
        return response.json();
    }
}

// Usage
const client = new TelegramClient('your-token');
client.sendMessage(1, 'Hello!').then(console.log);
```

## cURL Examples
```bash
# Sign up
curl -X POST https://decay1234.pythonanywhere.com/api/bot/signup \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test123","first_name":"Test"}'

# Send message
curl -X POST https://decay1234.pythonanywhere.com/api/bot{token}/sendMessage \
  -H "Content-Type: application/json" \
  -d '{"chat_id":1,"text":"Hello"}'
```

## Error Handling Example
```python
try:
    response = client.send_message(1, "Hello")
    if not response['ok']:
        print(f"Error {response['error_code']}: {response['description']}")
    else:
        print("Message sent:", response['result'])
except Exception as e:
    print("Request failed:", e)
```
```

```markdown
# Error Codes and Troubleshooting

## Common Error Codes

| Code | Description | Solution |
|------|-------------|----------|
| 400 | Bad Request | Check request parameters |
| 401 | Unauthorized | Provide valid token |
| 403 | Forbidden | Check user permissions |
| 404 | Not Found | Resource doesn't exist |
| 429 | Rate Limited | Reduce request frequency |
| 500 | Server Error | Contact administrator |

## Common Issues

### 1. Token Invalid
**Symptoms**: 401 Unauthorized errors
**Solution**: 
- Re-authenticate with signin method
- Check token format

### 2. Rate Limiting
**Symptoms**: 429 errors with retry_after
**Solution**:
- Implement request throttling
- Use batch operations when possible

### 3. Database Errors
**Symptoms**: 500 errors
**Solution**:
- Check database file permissions
- Verify database schema integrity

### 4. File Upload Issues
**Symptoms**: File upload fails
**Solution**:
- Check file size limits (100MB max)
- Verify upload directory permissions

## Debug Mode
Enable debug mode for detailed errors:
```python
app.config['DEBUG'] = True
```

## Logging
Check application logs for:
- Database queries
- Request processing
- Error details
```

```markdown
# Best Practices Guide

## Security
- Always use HTTPS in production
- Rotate secrets regularly
- Validate all input data
- Implement proper authentication

## Performance
- Use pagination for large datasets
- Implement caching where appropriate
- Optimize database queries
- Use connection pooling

## Rate Limiting
- Implement client-side throttling
- Handle 429 responses gracefully
- Use exponential backoff for retries

## Data Management
- Regular database backups
- Archive old messages
- Monitor database growth
- Implement data retention policies

## Error Handling
- Always check 'ok' field in responses
- Implement retry logic for transient errors
- Log errors for debugging
- Provide user-friendly error messages

## Testing
- Write unit tests for API methods
- Test edge cases and error conditions
- Perform load testing
- Test different user roles and permissions

## Monitoring
- Monitor API response times
- Track error rates
- Monitor database performance
- Set up alerts for critical issues
```
