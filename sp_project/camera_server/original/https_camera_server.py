#!/usr/bin/env python3
from flask import Flask, Response
import cv2
import time
import os
import socket

app = Flask(__name__)

# Global variables
camera = None

def get_camera():
    """Get camera object (lazy initialization)"""
    global camera
    if camera is None:
        # Use the same camera configuration
        camera = cv2.VideoCapture(1)
        # Set resolution
        camera.set(cv2.CAP_PROP_FRAME_WIDTH, 1280)
        camera.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)
        # Give the camera some time to start
        time.sleep(1)
    return camera

def gen_frames():
    """Generate video frames"""
    cam = get_camera()
    
    while True:
        success, frame = cam.read()
        if not success:
            print("Unable to read camera frame")
            break
        
        # Convert to JPEG
        ret, buffer = cv2.imencode('.jpg', frame)
        frame_bytes = buffer.tobytes()
        
        # Use multipart response format
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')
        
        # Control frame rate
        time.sleep(0.04)  # Approximately 25fps

@app.route('/')
def index():
    """Provide simple HTML page to preview camera"""
    # Get hostname for display
    hostname = get_hostname()
    
    return f"""
    <html>
      <head>
        <title>Facial Payment System Camera</title>
        <style>
          body {{ font-family: Arial; text-align: center; margin-top: 50px; }}
          img {{ max-width: 100%; border: 1px solid #ccc; }}
          .container {{ max-width: 800px; margin: 0 auto; }}
        </style>
      </head>
      <body>
        <div class="container">
          <h1>Facial Payment System Camera</h1>
          <img src="/video_feed" />
          <p>Secure facial recognition camera stream is running. Access via <strong>https://{hostname}:5443/video_feed</strong></p>
        </div>
      </body>
    </html>
    """

@app.route('/video_feed')
def video_feed():
    """Provide MJPEG video stream"""
    return Response(gen_frames(),
                   mimetype='multipart/x-mixed-replace; boundary=frame')

def get_hostname():
    """Get local IP address"""
    hostname = socket.gethostname()
    try:
        local_ip = socket.gethostbyname(hostname)
        return local_ip
    except:
        return "localhost"

def generate_ssl_cert():
    """Generate self-signed SSL certificate"""
    cert_dir = os.path.expanduser("./ssl_certs")
    os.makedirs(cert_dir, exist_ok=True)
    
    cert_file = os.path.join(cert_dir, "cert.pem")
    key_file = os.path.join(cert_dir, "key.pem")
    
    # Check if certificate already exists
    if os.path.exists(cert_file) and os.path.exists(key_file):
        print("Using existing SSL certificate")
        return cert_file, key_file
    
    # Generate new certificate
    print("Generating new self-signed SSL certificate...")
    
    try:
        from OpenSSL import crypto
    except ImportError:
        print("pyopenssl not installed, please run: pip install pyopenssl")
        exit(1)
    
    # Create key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)
    
    # Create self-signed certificate
    cert = crypto.X509()
    cert.get_subject().C = "CN"
    cert.get_subject().ST = "State"
    cert.get_subject().L = "City"
    cert.get_subject().O = "Organization"
    cert.get_subject().OU = "Organizational Unit"
    cert.get_subject().CN = socket.gethostname()
    
    # Set serial number
    import random
    cert.set_serial_number(random.randint(0, 2**64-1))
    
    # Set validity period
    import datetime
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)  # One year validity
    
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha256')
    
    # Write to files
    with open(cert_file, "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    
    with open(key_file, "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
    
    print(f"SSL certificate saved to: {cert_dir}")
    
    return cert_file, key_file

if __name__ == '__main__':
    # Generate SSL certificate
    cert_file, key_file = generate_ssl_cert()
    
    # Get local IP for display
    hostname = get_hostname()
    
    print(f"Facial Payment System camera server started at: https://{hostname}:5443")
    print(f"Facial recognition stream URL: https://{hostname}:5443/video_feed")
    print("Press Ctrl+C to stop the server")
    
    # Start HTTPS server, allow external access
    app.run(host='0.0.0.0', port=5443, ssl_context=(cert_file, key_file), threaded=True)