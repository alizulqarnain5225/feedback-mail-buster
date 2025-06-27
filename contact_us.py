import httpx
import time
import re
import gzip
import zlib
from datetime import datetime

def parse_raw_request(raw_request):
    """Parse a raw HTTP request into URL, headers, cookies, and form data."""
    lines = raw_request.strip().split('\n')
    
    # Extract method and path
    first_line = lines[0].split()
    method = first_line[0]
    path = first_line[1]
    
    # Extract headers
    headers = {}
    cookies = {}
    body_start = 0
    for i, line in enumerate(lines[1:], 1):
        if not line.strip():
            body_start = i + 1
            break
        if ': ' in line:
            key, value = line.split(': ', 1)
            headers[key] = value
            if key.lower() == 'cookie':
                cookie_pairs = value.split('; ')
                for pair in cookie_pairs:
                    if '=' in pair:
                        ckey, cvalue = pair.split('=', 1)
                        cookies[ckey] = cvalue
    
    # Remove Content-Length (httpx will set it automatically)
    headers.pop('Content-Length', None)
    # Force uncompressed response
    headers['Accept-Encoding'] = 'identity'
    
    # Construct URL
    host = headers.get('Host', '')
    scheme = 'https' if 'HTTP/2' in lines[0] else 'http'
    url = f"{scheme}://{host}{path}"
    
    # Parse multipart form data
    form_data = {}
    if 'Content-Type' in headers and 'multipart/form-data' in headers['Content-Type']:
        boundary = headers['Content-Type'].split('boundary=')[-1]
        body = '\n'.join(lines[body_start:]).strip()
        parts = body.split(f'--{boundary}')
        
        for part in parts:
            if 'Content-Disposition: form-data' in part:
                name_match = re.search(r'name="([^"]+)"', part)
                if name_match:
                    name = name_match.group(1)
                    value_lines = part.split('\n\n', 1)
                    if len(value_lines) > 1:
                        value = value_lines[1].strip()
                        form_data[name] = (None, value)
    
    return {
        'method': method,
        'url': url,
        'headers': headers,
        'cookies': cookies,
        'form_data': form_data
    }

def decode_response(response):
    """Decode response content, trying raw text first, then gzip or deflate."""
    content = response.content
    
    # Try decoding as raw text first
    try:
        return content.decode('utf-8', errors='replace'), content
    except UnicodeDecodeError:
        pass
    
    # Try gzip
    content_encoding = response.headers.get('Content-Encoding', '').lower()
    if content_encoding == 'gzip':
        try:
            content = gzip.decompress(response.content)
            return content.decode('utf-8', errors='replace'), response.content
        except Exception as e:
            return f"Error decoding gzip: {e}", response.content
    elif content_encoding == 'deflate':
        try:
            content = zlib.decompress(response.content)
            return content.decode('utf-8', errors='replace'), response.content
        except Exception as e:
            return f"Error decoding deflate: {e}", response.content
    
    return "Unable to decode response", response.content

def send_request(parsed_request):
    """Send the parsed HTTP request using httpx with HTTP/2 support."""
    try:
        with httpx.Client(http2=True, verify=False) as client:
            response = client.post(
                parsed_request['url'],
                headers=parsed_request['headers'],
                cookies=parsed_request['cookies'],
                files=parsed_request['form_data'],
                timeout=10
            )
        return response
    except Exception as e:
        return e

def main():
    # Read raw request from file
    try:
        with open('request.txt', 'r') as f:
            raw_request = f.read()
    except FileNotFoundError:
        print("Error: request.txt not found. Please create it and paste the raw HTTP request.")
        return
    
    # Parse the request
    parsed_request = parse_raw_request(raw_request)
    if not parsed_request['url']:
        print("Error: Could not parse the request. Check the format.")
        return
    
    print(f"Parsed URL: {parsed_request['url']}")
    print(f"Parsed Form Data: {dict((k, v[1]) for k, v in parsed_request['form_data'].items())}")
    print(f"Parsed Headers: {parsed_request['headers']}")
    print("-" * 50)
    
    # Open log file
    log_file = f"responses_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    
    # Main loop to send requests
    while True:
        try:
            # Send the request
            response = send_request(parsed_request)
            
            # Process response
            with open(log_file, 'a') as f:
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                if isinstance(response, Exception):
                    print(f"[{timestamp}] Error occurred: {response}")
                    f.write(f"[{timestamp}] Error: {response}\n")
                else:
                    decoded_content, raw_content = decode_response(response)
                    print(f"[{timestamp}] Status Code: {response.status_code}")
                    print(f"[{timestamp}] Response Headers: {dict(response.headers)}")
                    print(f"[{timestamp}] Response Body: {decoded_content[:500]}...")
                    f.write(f"[{timestamp}] Request Headers: {parsed_request['headers']}\n")
                    f.write(f"[{timestamp}] Request Cookies: {parsed_request['cookies']}\n")
                    f.write(f"[{timestamp}] Request Form Data: {dict((k, v[1]) for k, v in parsed_request['form_data'].items())}\n")
                    f.write(f"[{timestamp}] Status Code: {response.status_code}\n")
                    f.write(f"[{timestamp}] Response Headers: {dict(response.headers)}\n")
                    f.write(f"[{timestamp}] Response Body: {decoded_content}\n")
                    # Save raw response to a separate file
                    raw_file = f"raw_response_{timestamp.replace(' ', '_').replace(':', '')}.bin"
                    with open(raw_file, 'wb') as rf:
                        rf.write(raw_content)
                    f.write(f"[{timestamp}] Raw Response Saved To: {raw_file}\n")
                
                f.write("-" * 50 + "\n")
            
            print("-" * 50)
            
            # Wait for 2 seconds
            time.sleep(1)
            
        except KeyboardInterrupt:
            print("\nStopped by user.")
            break
        except Exception as e:
            print(f"Unexpected error: {e}")
            with open(log_file, 'a') as f:
                f.write(f"[{timestamp}] Unexpected error: {e}\n")
                f.write("-" * 50 + "\n")
            print("-" * 50)
            time.sleep(2)

if __name__ == "__main__":
    main()
