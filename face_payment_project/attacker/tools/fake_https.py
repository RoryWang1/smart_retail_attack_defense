#!/usr/bin/python3
from flask import Flask, Response, render_template_string, request
import cv2
import os
import time
import numpy as np
import logging
import ssl
import socket
import sys
import random
import datetime
try:
    from OpenSSL import crypto
except ImportError:
    print("Error: pyopenssl library not installed. Please install it: pip install pyopenssl", file=sys.stderr)
    sys.exit(1)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CERT_DIR = os.path.join(BASE_DIR, "certs")
MEDIA_DIR = os.path.join(BASE_DIR, "media", "videos")
LATEST_VIDEO = os.path.join(MEDIA_DIR, "latest.mp4")
LISTEN_HOST = '0.0.0.0'
LISTEN_PORT = 443
FRAME_WIDTH = 640
FRAME_HEIGHT = 480
FPS = 20

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("FakeHttpsServer")

app = Flask(__name__)

os.makedirs(CERT_DIR, exist_ok=True)
os.makedirs(MEDIA_DIR, exist_ok=True)
logger.info(f"Ensured certificate directory exists: {CERT_DIR}")
logger.info(f"Video directory: {MEDIA_DIR}")

def create_default_image():
    """Create default red 'INTERCEPTED' image when video is unavailable"""
    img = np.zeros((FRAME_HEIGHT, FRAME_WIDTH, 3), dtype=np.uint8)
    img[:, :, 2] = 255 # Red background
    cv2.putText(img, "INTERCEPTED", (int(FRAME_WIDTH*0.1), int(FRAME_HEIGHT/2)), cv2.FONT_HERSHEY_SIMPLEX,
                2, (255, 255, 255), 3, cv2.LINE_AA)
    cv2.putText(img, "No video file available", (int(FRAME_WIDTH*0.1), int(FRAME_HEIGHT/2 + 50)), 
                cv2.FONT_HERSHEY_SIMPLEX, 0.7, (255, 255, 255), 2, cv2.LINE_AA)
    return img

def generate_ssl_cert():
    """Generate self-signed SSL certificate if it doesn't exist"""
    cert_file = os.path.join(CERT_DIR, "fake_cert.pem")
    key_file = os.path.join(CERT_DIR, "fake_key.pem")

    if os.path.exists(cert_file) and os.path.exists(key_file):
        logger.info(f"Using existing fake SSL certificate: {cert_file}")
        return cert_file, key_file

    logger.info("Generating new fake self-signed SSL certificate...")
    try:
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)

        cert = crypto.X509()
        subj = cert.get_subject()
        subj.C = "XX" 
        subj.ST = "State"
        subj.L = "City"
        subj.O = "Fake Org"
        subj.OU = "Fake OU"
        try:
             subj.CN = socket.gethostname()
        except Exception:
             logger.warning("Could not get hostname, using 'localhost' as CN.")
             subj.CN = "localhost"

        cert.set_serial_number(random.randint(0, 2**64-1))
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365*24*60*60)
        cert.set_issuer(subj)
        cert.set_pubkey(k)
        cert.sign(k, 'sha256')

        with open(cert_file, "wb") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        with open(key_file, "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
        logger.info(f"Fake SSL certificate created: {cert_file}")
    except Exception as e:
        logger.error(f"Error generating fake SSL certificate files: {e}", exc_info=True)
        sys.exit(1)

    return cert_file, key_file

def gen_video_frames():
    """Generate video frames in a loop from latest.mp4 file"""
    logger.info(f"Starting video frame generation from: {LATEST_VIDEO}")
    
    default_frame = create_default_image()
    frame_count = 0
    video_available = False
    
    if not os.path.exists(LATEST_VIDEO):
        logger.warning(f"Video file not found: {LATEST_VIDEO}")
        logger.info("Using default intercepted image instead")
        video_available = False
    else:
        logger.info(f"Found video file: {LATEST_VIDEO}")
        video_available = True
    
    while True:
        try:
            if video_available:
                cap = cv2.VideoCapture(LATEST_VIDEO)
                if not cap.isOpened():
                    logger.error(f"Could not open video file: {LATEST_VIDEO}")
                    video_available = False
                    yield_default_frame(default_frame, frame_count)
                    frame_count += 1
                    continue
                
                logger.info("Starting video playback")
                while cap.isOpened():
                    ret, frame = cap.read()
                    if not ret:
                        logger.info("Reached end of video, restarting...")
                        break
                    
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                    cv2.putText(frame, f"Frame: {frame_count}", (10, frame.shape[0] - 50),
                                cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1, cv2.LINE_AA)
                    cv2.putText(frame, timestamp, (10, frame.shape[0] - 20),
                                cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1, cv2.LINE_AA)
                    
                    ret, buffer = cv2.imencode('.jpg', frame)
                    if not ret:
                        logger.warning("Failed to encode video frame")
                        continue
                    
                    frame_bytes = buffer.tobytes()
                    yield (b'--frame\r\n'
                           b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')
                    
                    frame_count += 1
                    
                    time.sleep(1.0 / FPS)
                
                cap.release()
                
                if os.path.exists(LATEST_VIDEO):
                    mod_time = os.path.getmtime(LATEST_VIDEO)
                    if time.time() - mod_time < 15:  # If file was modified in last 15 seconds
                        logger.info("Video file has been updated, reloading...")
                
            else:
                yield_frame = default_frame.copy()
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                cv2.putText(yield_frame, f"Frame: {frame_count}", (10, FRAME_HEIGHT - 50),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1, cv2.LINE_AA)
                cv2.putText(yield_frame, timestamp, (10, FRAME_HEIGHT - 20),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1, cv2.LINE_AA)
                
                ret, buffer = cv2.imencode('.jpg', yield_frame)
                if not ret:
                    logger.warning("Failed to encode default image")
                    time.sleep(1.0 / FPS)
                    continue
                
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + buffer.tobytes() + b'\r\n')
                
                frame_count += 1
                
                if frame_count % (FPS * 5) == 0:
                    if os.path.exists(LATEST_VIDEO):
                        video_available = True
                        logger.info(f"Video file now available: {LATEST_VIDEO}")
                
                time.sleep(1.0 / FPS)
            
        except GeneratorExit:
            logger.info(f"Client disconnected after {frame_count} frames.")
            break
        except Exception as e:
            logger.error(f"Error in frame generator: {e}", exc_info=True)
            time.sleep(1)

@app.route('/')
def index():
    """Basic HTML page to view the stream"""
    return render_template_string("""
    <!DOCTYPE html>
    <html><head><title>Fake HTTPS Stream</title></head>
    <body><h1>Fake HTTPS Video Stream (Intercepted)</h1>
    <img src="/video_feed" width="{{width}}" height="{{height}}">
    <p>Status: Playing video from latest.mp4</p>
    </body></html>
    """, width=FRAME_WIDTH, height=FRAME_HEIGHT)

@app.route('/video_feed')
@app.route('/feed')
def video_feed():
    """Endpoint for the MJPEG stream"""
    logger.info(f"Request for video feed from {request.remote_addr}")
    response = Response(
        gen_video_frames(),
        mimetype='multipart/x-mixed-replace; boundary=frame'
    )
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['Connection'] = 'close'
    return response

if __name__ == '__main__':
    logger.info("--- Fake HTTPS Server Starting ---")
    logger.info(f"Looking for video file: {LATEST_VIDEO}")
    
    if os.path.exists(LATEST_VIDEO):
        logger.info(f"Found video file: {LATEST_VIDEO}")
    else:
        logger.warning(f"Video file not found: {LATEST_VIDEO}")
        logger.info("Will use default intercepted image until video is available")
    
    try:
        cert_file, key_file = generate_ssl_cert()

        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            ssl_context.load_cert_chain(cert_file, key_file)
            logger.info("SSL context loaded successfully.")
        except Exception as e:
             logger.error(f"Failed to load SSL context: {e}", exc_info=True)
             sys.exit(1)

        logger.info(f"Attempting to start HTTPS server on https://{LISTEN_HOST}:{LISTEN_PORT}")
        logger.info("NOTE: This requires root privileges (run with sudo).")
        app.run(host=LISTEN_HOST, port=LISTEN_PORT, ssl_context=ssl_context, threaded=True, debug=False, use_reloader=False)

    except PermissionError:
        logger.error(f"CRITICAL ERROR: Permission denied to bind to port {LISTEN_PORT}.")
        logger.error("Please run this script using 'sudo'.")
        sys.exit(1)
    except OSError as e:
        if e.errno == 98:
             logger.error(f"CRITICAL ERROR: Port {LISTEN_PORT} is already in use.")
             logger.error("Please check if another service (or another instance of this script) is running on this port.")
        else:
             logger.error(f"CRITICAL ERROR starting server (OSError): {e}", exc_info=True)
        sys.exit(1)
    except Exception as e:
        logger.error(f"CRITICAL ERROR starting server (General Exception): {e}", exc_info=True)
        sys.exit(1)