#!/usr/bin/env python3
from flask import Flask, Response
import cv2
import time
import os
import socket
import numpy as np
import threading
import subprocess
import logging

logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

camera = None
camera_lock = threading.Lock()
FALLBACK_MODE = False  # Enable fallback mode when camera is unavailable

def create_fallback_image():
    img = np.zeros((480, 640, 3), dtype=np.uint8)
    img[:, :] = (255, 0, 0)  # Blue background
    font = cv2.FONT_HERSHEY_SIMPLEX
    cv2.putText(img, "CAMERA UNAVAILABLE", (100, 240), font, 1, (255, 255, 255), 2)
    cv2.putText(img, "Server running in fallback mode", (80, 280), font, 0.7, (255, 255, 255), 1)
    return img

FALLBACK_IMAGE = create_fallback_image()

def safe_get_camera():
    """Safely get camera instance"""
    global camera, FALLBACK_MODE
    
    with camera_lock:
        if camera is None:
            logger.info("Initializing camera...")
            try:
                # Use simplest camera initialization method
                camera = cv2.VideoCapture(0)
                if not camera.isOpened():
                    logger.error("Camera cannot be opened, switching to fallback mode")
                    FALLBACK_MODE = True
                    return None
                else:
                    logger.info("Camera successfully initialized")
                    FALLBACK_MODE = False
            except Exception as e:
                logger.error(f"Camera initialization error: {e}")
                FALLBACK_MODE = True
                return None
        return camera

def safe_release_camera():
    """Safely release camera"""
    global camera
    with camera_lock:
        if camera is not None:
            try:
                camera.release()
                logger.info("Camera released")
            except Exception as e:
                logger.error(f"Error releasing camera: {e}")
            camera = None

def generate_frames():
    """Generator function for video frames"""
    global FALLBACK_MODE, FALLBACK_IMAGE
    
    # Try reopening camera every 5 failures
    failure_count = 0
    max_consecutive_failures = 5
    frame_count = 0
    
    logger.info("Starting video frame generation")
    
    try:
        while True:
            if FALLBACK_MODE:
                # Use fallback static image, but add timestamp for variation
                img = FALLBACK_IMAGE.copy()
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                cv2.putText(img, timestamp, (10, 460), cv2.FONT_HERSHEY_SIMPLEX, 
                            0.7, (255, 255, 255), 1)
                
                # Try to recover camera every 30 frames
                if frame_count % 30 == 0:
                    logger.info("Attempting to recover camera...")
                    safe_release_camera()
                    if safe_get_camera() is not None:
                        FALLBACK_MODE = False
                        logger.info("Camera recovered")
                
                ret, buffer = cv2.imencode('.jpg', img)
                if not ret:
                    logger.warning("Static image encoding failed")
                    time.sleep(0.1)
                    continue
                
                frame_bytes = buffer.tobytes()
                
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')
                
                time.sleep(0.1)  # About 10fps, reduce frame rate in fallback mode to save resources
                frame_count += 1
                continue
            
            cam = safe_get_camera()
            if cam is None:
                FALLBACK_MODE = True
                continue
            
            success = False
            try:
                with camera_lock:
                    success, frame = cam.read()
            except Exception as e:
                logger.error(f"Error reading camera frame: {e}")
                success = False
            
            if not success:
                failure_count += 1
                logger.warning(f"Camera frame read failed ({failure_count}/{max_consecutive_failures})")
                
                if failure_count >= max_consecutive_failures:
                    logger.error("Consecutive read failures, switching to fallback mode")
                    FALLBACK_MODE = True
                    failure_count = 0
                
                time.sleep(0.1)
                continue
            
            failure_count = 0
            
            try:
                ret, buffer = cv2.imencode('.jpg', frame)
                if not ret:
                    logger.warning("Encoding failed")
                    time.sleep(0.1)
                    continue
                
                frame_bytes = buffer.tobytes()
                
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')
                
                time.sleep(0.04)  # About 25fps
                frame_count += 1
            except Exception as e:
                logger.error(f"Error processing frame: {e}")
                time.sleep(0.1)
                
    except GeneratorExit:
        logger.info("Video stream generator closed (client disconnected)")
    except Exception as e:
        logger.error(f"Video stream generator serious error: {e}")
    finally:
        logger.info("Video stream generator ended")

@app.route('/')
def index():
    """Home page showing video stream"""
    hostname = socket.gethostname()
    try:
        hostname = socket.gethostbyname(hostname)
    except:
        hostname = "localhost"
    
    return f"""
    <html>
      <head>
        <title>Simple Camera Server</title>
        <style>
          body {{ font-family: Arial; text-align: center; margin-top: 50px; }}
          img {{ max-width: 100%; border: 1px solid #ccc; }}
          .container {{ max-width: 800px; margin: 0 auto; }}
        </style>
      </head>
      <body>
        <div class="container">
          <h1>Camera Stream</h1>
          <img src="/video_feed" />
          <p>Video stream URL: <strong>https://{hostname}:5443/video_feed</strong></p>
        </div>
      </body>
    </html>
    """

@app.route('/video_feed')
def video_feed():
    """Video stream endpoint"""
    try:
        return Response(generate_frames(),
                       mimetype='multipart/x-mixed-replace; boundary=frame',
                       headers={
                           'Cache-Control': 'no-cache, private',
                           'Pragma': 'no-cache',
                           'Expires': '0'
                       })
    except Exception as e:
        logger.error(f"Error creating video stream response: {e}")
        return "Video stream error", 500

@app.route('/status')
def status():
    """Server status endpoint"""
    global FALLBACK_MODE
    return {
        "status": "running", 
        "mode": "fallback" if FALLBACK_MODE else "normal",
        "time": time.strftime("%Y-%m-%d %H:%M:%S")
    }

@app.errorhandler(Exception)
def handle_error(e):
    """Global error handler"""
    logger.error(f"Request processing error: {e}")
    return "Server error", 500

def generate_ssl_cert():
    """Generate self-signed SSL certificate"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    cert_dir = os.path.join(script_dir, "certs")
    os.makedirs(cert_dir, exist_ok=True)
    
    cert_file = os.path.join(cert_dir, "cert.pem")
    key_file = os.path.join(cert_dir, "key.pem")
    
    if os.path.exists(cert_file) and os.path.exists(key_file):
        logger.info("Using existing SSL certificate")
        return cert_file, key_file
    
    logger.info("Generating new SSL certificate...")
    
    try:
        from OpenSSL import crypto
    except ImportError:
        logger.error("Missing pyopenssl, please install: pip install pyopenssl")
        exit(1)
    
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)
    
    cert = crypto.X509()
    cert.get_subject().C = "CN"
    cert.get_subject().ST = "State"
    cert.get_subject().L = "City"
    cert.get_subject().O = "Organization"
    cert.get_subject().CN = socket.gethostname()
    
    import random
    cert.set_serial_number(random.randint(0, 2**64-1))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)  # Valid for one year
    
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha256')
    
    with open(cert_file, "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    
    with open(key_file, "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
    
    logger.info(f"SSL certificate saved to: {cert_dir}")
    return cert_file, key_file

def cleanup():
    """Cleanup function on exit"""
    logger.info("Program exiting, cleaning up resources...")
    safe_release_camera()

if __name__ == '__main__':
    import atexit
    atexit.register(cleanup)
    
    cert_file, key_file = generate_ssl_cert()
    
    logger.info("Starting camera server...")
    logger.info(f"Server will listen on 0.0.0.0:5443")
    
    try:
        app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
        app.config['PROPAGATE_EXCEPTIONS'] = False
        
        app.run(host='0.0.0.0', 
                port=5443, 
                ssl_context=(cert_file, key_file),
                threaded=True,
                debug=False)
    except Exception as e:
        logger.error(f"Server startup error: {e}")
    finally:
        cleanup()
