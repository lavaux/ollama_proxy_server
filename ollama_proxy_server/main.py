"""
project: ollama_proxy_server
file: main.py
author: ParisNeo
description: This is a proxy server that adds a security layer to one or multiple ollama servers and routes the requests to the right server in order to minimize the charge of the server.
"""

import configparser
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs
from queue import Queue
import requests
import argparse
from ascii_colors import ASCIIColors
from pathlib import Path
import csv
import datetime
from ascii_colors import ASCIIColors, trace_exception
import bcrypt
import os
import sys

ALLOWED_PATHS = {
    '/api/generate',
    '/api/show',
    '/api/ps',
    '/api/chat',
    '/api/embed',
    '/v1/chat/completions',
    '/api/tags',  # Example of another valid endpoint
    '/',
}

def is_path_allowed(path: str) -> bool:
    """Check if the path is in the allowlist."""
    return path in ALLOWED_PATHS

def sanitize_path(path: str) -> str:
    """Sanitize the path to prevent traversal attacks."""
    if not is_path_allowed(path):
        raise ValueError(f"Path not allowed: {path}")
    if '../' in path or '//' in path:
        raise ValueError(f"Path traversal attempt detected: {path}")
    return path

def get_config(filename: str) -> list:
    """Read and validate the config file."""
    config = configparser.ConfigParser()
    config.read(filename)

    servers = []
    for name in config.sections():
        try:
            url = config[name]['url']
            if not url.startswith(('http://', 'https://')):
                raise ValueError(f"Invalid URL for server {name}: {url}")

            max_connections = int(config[name].get('max_parallel_connections', 10))
            queue_size = int(config[name].get('queue_size', 100))

            if max_connections <= 0 or queue_size <= 0:
                raise ValueError(f"Invalid queue or connection settings for server {name}")

            servers.append((
                name,
                {
                    'url': url,
                    'max_parallel_connections': max_connections,
                    'queue_size': queue_size,
                    'queue': Queue(maxsize=queue_size),
                    'active_requests': 0
                }
            ))
        except Exception as e:
            ASCIIColors.red(f"Invalid config for server {name}: {str(e)}")
            raise

    return servers

def hash_key(key: str) -> str:
    """Hash a key using bcrypt."""
    return bcrypt.hashpw(key.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_key(plain_key: str, hashed_key: str) -> bool:
    """Verify a plain key against a hashed key."""
    return bcrypt.checkpw(plain_key.encode('utf-8'), hashed_key.encode('utf-8'))

def get_authorized_users(filename: str) -> dict:
    """Read authorized users and their hashed keys from a file."""
    authorized_users = {}
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    user, hashed_key = line.split(':')
                    authorized_users[user] = hashed_key
                except ValueError:
                    ASCIIColors.red(f"Invalid user entry (expected 'user:hashed_key'): {line}")
    except FileNotFoundError:
        ASCIIColors.red(f"Authorized users file not found: {filename}")
        raise
    return authorized_users

def display_config(args, servers, authorized_users):
    print("\n🌟 Current Configuration 🌟")
    ASCIIColors.blue(f"📁 Config File: {args.config}")
    ASCIIColors.blue(f"🗄️ Log Path: {args.log_path}")
    ASCIIColors.blue(f"👤 Users List: {args.users_list}")
    ASCIIColors.blue(f"🔢 Port Number: {args.port}")
    ASCIIColors.yellow(
        f"⚠️ Security Deactivation: "
        f"{'ENABLED (DEV ONLY!)' if args.deactivate_security else 'Disabled ✅'}"
    )

    # Additional config details
    if servers:
        print("\n🌐 Servers Configuration:")
        for server in servers:
            ASCIIColors.green(f"  {server[0]}: {server[1]}")

    print("\n🔑 Authorized Users:")
    for user in authorized_users:
        ASCIIColors.yellow(f"  - 👤 {user}")
        
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default="config.ini", help='Path to the config file')
    parser.add_argument('--log_path', default="access_log.txt", help='Path to the access log file')
    parser.add_argument('--users_list', default="authorized_users.txt", help='Path to the authorized users list')
    parser.add_argument('--port', type=int, default=11534, help='Port number for the server (default is 100 + default ollama port number)')
    parser.add_argument('-d', '--deactivate_security', action='store_true', help='Deactivates security')

    args = parser.parse_args()
    servers = get_config(args.config)
    authorized_users = get_authorized_users(args.users_list)

    ASCIIColors.red("Ollama Proxy Server")
    ASCIIColors.multicolor(["Author:", "ParisNeo"], [ASCIIColors.color_red, ASCIIColors.color_magenta])

    # Display the current configuration
    display_config(args, servers, authorized_users)

    # Later in the code:
    if args.deactivate_security and not os.getenv('DEV_MODE', 'false').lower() == 'true':
        ASCIIColors.red("⚠️ Security deactivation is only allowed in DEV_MODE!")
        sys.exit(1)

    class RequestHandler(BaseHTTPRequestHandler):
        def add_access_log_entry(self, event, user, ip_address, access, server, nb_queued_requests_on_server, error=""):
            log_file_path = Path(args.log_path)
            try:
                if not log_file_path.exists():
                    with open(log_file_path, mode='w', newline='') as csvfile:
                        fieldnames = ['time_stamp', 'event', 'user_name', 'ip_address', 'access', 'server', 'nb_queued_requests_on_server', 'error']
                        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                        writer.writeheader()

                with open(log_file_path, mode='a', newline='') as csvfile:
                    fieldnames = ['time_stamp', 'event', 'user_name', 'ip_address', 'access', 'server', 'nb_queued_requests_on_server', 'error']
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    row = {'time_stamp': str(datetime.datetime.now()), 'event': event, 'user_name': user, 'ip_address': ip_address, 'access': access, 'server': server, 'nb_queued_requests_on_server': nb_queued_requests_on_server, 'error': error}
                    writer.writerow(row)
            except Exception as ex:
                trace_exception(ex)
        def _send_response(self, response):
            self.send_response(response.status_code)
            for key, value in response.headers.items():
                if key.lower() not in ['content-length', 'transfer-encoding', 'content-encoding']:
                    self.send_header(key, value)
            self.end_headers()

            try:
                # Read the full content to avoid chunking issues
                content = response.content
                self.wfile.write(content)
                self.wfile.flush()
            except BrokenPipeError:
                pass

        def do_HEAD(self):
            self.log_request()
            self.proxy()

        def do_GET(self):
            self.log_request()
            self.proxy()

        def do_POST(self):
            self.log_request()
            self.proxy()

        def _validate_user_and_key(self) -> bool:
            """Validate the user and key from the Authorization header."""
            try:
                auth_header = self.headers.get('Authorization')
                if not auth_header or not auth_header.startswith('Bearer '):
                    return False
        
                # Extract token (user:key)
                token = auth_header.split(' ')[1]
                if ':' not in token:
                    return False  # Malformed token
        
                user, plain_key = token.split(':', 1)  # Split on first colon only
                if user not in authorized_users:
                    return False  # User not found
        
                # Verify the key against the hashed value
                hashed_key = authorized_users[user]
                if not verify_key(plain_key, hashed_key):
                    return False  # Key mismatch
        
                self.user = user
                return True
     
            except Exception as e:
                ASCIIColors.red(f"Token validation error: {str(e)}")
                return False

        def proxy(self):
            self.user = "unknown"
            if not args.deactivate_security and not self._validate_user_and_key():
                ASCIIColors.red(f'User is not authorized')
                client_ip, client_port = self.client_address
                # Extract the bearer token from the headers
                auth_header = self.headers.get('Authorization')
                if not auth_header or not auth_header.startswith('Bearer '):
                    self.add_access_log_entry(event='rejected', user="unknown", ip_address=client_ip, access="Denied", server="None", nb_queued_requests_on_server=-1, error="Authentication failed")
                else:
                    token = auth_header.split(' ')[1]
                    self.add_access_log_entry(event='rejected', user=token, ip_address=client_ip, access="Denied", server="None", nb_queued_requests_on_server=-1, error="Authentication failed")
                self.send_response(403)
                self.end_headers()
                return

            url = urlparse(self.path)
            path = url.path
            get_params = parse_qs(url.query) or {}


            try:
                sanitized_path = sanitize_path(url.path)
            except ValueError as e:
                ASCIIColors.red(f"Path validation failed: {str(e)}")
                self.send_response(403)
                self.end_headers()
                self.add_access_log_entry(
                    event="invalid_path",
                    user=self.user,
                    ip_address=self.client_address[0],
                    access="Denied",
                    server="None",
                    nb_queued_requests_on_server=-1,
                    error=str(e)
                )
                return
        
            if self.command == "POST":
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                post_params = post_data# parse_qs(post_data.decode('utf-8'))
            else:
                post_params = {}
                post_data = None

            # Find the server with the lowest number of active requests.
            min_active_server = servers[0]
            for server in servers:
                cs = server[1]
                if cs['active_requests'] < min_active_server[1]['active_requests']:
                    min_active_server = server

            # Apply the queuing mechanism only for a specific endpoint.
            if path == '/api/generate' or path == '/api/chat' or path == '/v1/chat/completions':
                cs = min_active_server[1]
                client_ip, client_port = self.client_address
                try:
                    # Try to acquire the queue slot for this request.
                    cs['queue'].put_nowait(1)
                    self.add_access_log_entry(event="gen_request", user=self.user, ip_address=client_ip, access="Authorized", server=min_active_server[0], nb_queued_requests_on_server=cs['active_requests'])
                except Queue.Full:
                    # If the queue is full, log and return a 503 Service Unavailable response.
                    self.add_access_log_entry(event="gen_error", user=self.user, ip_address=client_ip, access="Authorized", server=min_active_server[0], nb_queued_requests_on_server=cs['active_requests'], error="Queue is full")
                    self.send_response(503)
                    self.end_headers()
                    return

                try:
                    post_data_dict = {}

                    if isinstance(post_data, bytes):
                        try:
                            post_data_str = post_data.decode('utf-8')
                            post_data_dict = json.loads(post_data_str)
                        except json.JSONDecodeError:
                            ASCIIColors.red("Invalid JSON payload")
                            cs['queue'].get_nowait()
                            self.send_response(400)
                            self.end_headers()
                            self.add_access_log_entry(
                                event="invalid_json",
                                user=self.user,
                                ip_address=self.client_address[0],
                                access="Denied",
                                server="None",
                                nb_queued_requests_on_server=-1,
                                error="Malformed JSON"
                            )
                            return

                    response = requests.request(self.command, cs['url'] + path, params=get_params, data=post_params, stream=post_data_dict.get("stream", False))
                    self._send_response(response)
                finally:
                    cs['queue'].get_nowait()
                    self.add_access_log_entry(event="gen_done", user=self.user, ip_address=client_ip, access="Authorized", server=min_active_server[0], nb_queued_requests_on_server=cs['active_requests'])
            else:
                # For other endpoints, just mirror the request.
                response = requests.request(self.command, min_active_server[1]['url'] + path, params=get_params, data=post_params)
                self._send_response(response)

    class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
        pass

    print('Starting server')
    server = ThreadedHTTPServer(('', args.port), RequestHandler)  # Set the entry port here.
    print(f'Running server on port {args.port}')
    server.serve_forever()

if __name__ == "__main__":
    main()
