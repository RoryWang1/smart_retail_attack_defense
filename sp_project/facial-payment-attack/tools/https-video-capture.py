#!/usr/bin/python3
import cv2
import time
import os
import argparse
import ssl
import urllib3
import numpy as np
import requests
from datetime import datetime
from PIL import Image
from io import BytesIO
import threading
import queue

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Global frame queue
frame_queue = queue.Queue(maxsize=300)  # Allow caching more frames
stop_event = threading.Event()

def fetch_frames_thread(url):
    """Fetch frames in a separate thread"""
    print(f"Fetching frames from HTTPS stream in separate thread: {url}")
    
    # Create session and disable certificate verification
    session = requests.Session()
    session.verify = False
    
    # Increase timeout and buffer size
    session.timeout = 10
    
    # Number of connection attempts
    retry_count = 0
    max_retries = 3
    
    while not stop_event.is_set() and retry_count < max_retries:
        try:
            # Establish streaming connection
            print(f"Attempting to connect to HTTPS stream (attempt {retry_count+1}/{max_retries})...")
            response = session.get(url, stream=True, timeout=10)
            
            if response.status_code != 200:
                print(f"HTTP error: {response.status_code}")
                retry_count += 1
                time.sleep(1)
                continue
                
            print("Successfully connected to HTTPS video stream")
            retry_count = 0  # Reset retry counter
            
            # Check content type
            content_type = response.headers.get('content-type', '')
            if 'multipart/x-mixed-replace' not in content_type:
                print(f"Unsupported content type: {content_type}")
                retry_count += 1
                time.sleep(1)
                continue
                
            # Get boundary string
            boundary = content_type.split('boundary=')[1]
            boundary_bytes = f'--{boundary}'.encode()
            
            # Initialize buffer
            buffer = bytes()
            frames_captured = 0
            
            # Read data from stream
            for chunk in response.iter_content(chunk_size=8192):  # Use larger chunk size
                if stop_event.is_set():
                    break
                    
                if not chunk:
                    continue
                
                # Append to buffer
                buffer += chunk
                
                # Loop to extract all complete frames
                while True:
                    # Find frame boundary
                    start_idx = buffer.find(boundary_bytes)
                    if start_idx == -1:
                        break
                        
                    # Find next frame boundary
                    next_idx = buffer.find(boundary_bytes, start_idx + len(boundary_bytes))
                    if next_idx == -1:
                        break
                    
                    # Extract a complete frame
                    frame_data = buffer[start_idx:next_idx]
                    # Update buffer, remove processed part
                    buffer = buffer[next_idx:]
                    
                    # Extract JPEG image data from frame
                    try:
                        jpeg_start = frame_data.find(b'\r\n\r\n')
                        if jpeg_start != -1:
                            jpeg_data = frame_data[jpeg_start + 4:]
                            
                            # Ensure valid JPEG data 
                            if len(jpeg_data) > 100:  # Simple size check
                                # Convert JPEG data to NumPy array
                                nparr = np.frombuffer(jpeg_data, np.uint8)
                                img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
                                
                                if img is not None and img.size > 0:
                                    # If queue is full, remove oldest frame
                                    if frame_queue.full():
                                        try:
                                            frame_queue.get_nowait()
                                        except queue.Empty:
                                            pass
                                    
                                    # Add frame to queue
                                    frame_queue.put(img)
                                    frames_captured += 1
                                    
                                    # Print progress
                                    if frames_captured % 10 == 0:
                                        print(f"Captured {frames_captured} frames (queue size: {frame_queue.qsize()})")
                    except Exception as e:
                        print(f"Error processing frame: {e}")
                        
            # If loop ends normally, reconnect
            print("Stream data ended, attempting to reconnect...")
            
        except Exception as e:
            print(f"HTTPS stream capture error: {e}")
            retry_count += 1
            time.sleep(2)

def capture_video(url, output_dir, duration=10, fps=25, face_only=True):
    """Capture video and save"""
    global stop_event
    
    # Reset stop event
    stop_event.clear()
    
    # Ensure output directory exists
    os.makedirs(os.path.expanduser(output_dir), exist_ok=True)
    video_dir = os.path.join(os.path.expanduser(output_dir), "videos")
    os.makedirs(video_dir, exist_ok=True)
    
    # Check if HTTPS URL
    is_https = url.startswith('https://')
    
    frames = []
    
    if is_https:
        print("HTTPS URL detected, using multi-threaded processing...")
        
        # Create window
        cv2.namedWindow('HTTPS Video Capture', cv2.WINDOW_NORMAL)
        
        # Start frame fetching thread
        fetch_thread = threading.Thread(target=fetch_frames_thread, args=(url,))
        fetch_thread.daemon = True
        fetch_thread.start()
        
        # Wait a while to ensure connection established
        time.sleep(3)
        
        # Main loop for collecting frames
        start_time = time.time()
        frames_displayed = 0
        
        # Create initial screen
        waiting_frame = np.zeros((480, 640, 3), dtype=np.uint8)
        cv2.putText(waiting_frame, "Waiting for frames...", (240, 240), 
                  cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 255, 255), 2)
        cv2.imshow('HTTPS Video Capture', waiting_frame)
        cv2.waitKey(1)
        
        while time.time() - start_time < duration:
            try:
                # Get frame in non-blocking way
                frame = frame_queue.get(timeout=0.1)
                frames.append(frame)
                frames_displayed += 1
                
                # Show preview
                preview = frame.copy()
                cv2.putText(preview, f"Captured frame #{frames_displayed}", (10, 30), 
                          cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0), 2)
                cv2.putText(preview, f"Time remaining: {int(duration - (time.time() - start_time))}s", 
                          (10, 60), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0), 2)
                cv2.imshow('HTTPS Video Capture', preview)
                
                if cv2.waitKey(1) & 0xFF == ord('q'):
                    print("User interrupted capture")
                    break
            except queue.Empty:
                # If queue is empty, wait a bit
                waiting_frame = np.zeros((480, 640, 3), dtype=np.uint8)
                cv2.putText(waiting_frame, "Waiting for frames...", (240, 240), 
                          cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 255, 255), 2)
                cv2.putText(waiting_frame, f"Time remaining: {int(duration - (time.time() - start_time))}s", 
                          (240, 280), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (255, 255, 255), 1)
                cv2.imshow('HTTPS Video Capture', waiting_frame)
                cv2.waitKey(1)
                time.sleep(0.1)
                
        # Stop fetching thread
        stop_event.set()
        fetch_thread.join(timeout=2)
        
        print(f"Capture ended, retrieved {len(frames)} frames")
    else:
        print(f"Connecting to HTTP camera stream: {url}")
        
        # Use standard OpenCV method to capture HTTP stream
        cap = cv2.VideoCapture(url)
        if not cap.isOpened():
            print("Cannot connect to camera stream, please check URL")
            return False
            
        # Read frames
        start_time = time.time()
        frame_count = 0
        
        while time.time() - start_time < duration:
            ret, frame = cap.read()
            if not ret:
                print("Cannot read video frame, trying to reconnect...")
                time.sleep(0.5)
                cap = cv2.VideoCapture(url)
                continue
                
            frames.append(frame)
            frame_count += 1
            
            # Show preview
            preview = frame.copy()
            cv2.putText(preview, f"Captured frame #{frame_count}", (10, 30), 
                      cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0), 2)
            cv2.imshow('Video Capture', preview)
            
            if cv2.waitKey(1) & 0xFF == ord('q'):
                print("User interrupted capture")
                break
                
            # Control capture framerate
            time.sleep(1.0/fps)
            
        # Release resources
        cap.release()
    
    # Process captured frames
    if len(frames) == 0:
        print("No valid frames captured, exiting")
        cv2.destroyAllWindows()
        return None

    print(f"Processing {len(frames)} frames...")
        
    # Use first frame to get dimensions
    first_frame = frames[0]
    frame_height, frame_width = first_frame.shape[:2]
    
    # Create video filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    protocol = "https" if is_https else "http"
    video_filename = os.path.join(video_dir, f"captured_{protocol}_video_{timestamp}.mp4")
    latest_link = os.path.join(video_dir, "latest_video.mp4")
    
    # Create video writer
    fourcc = cv2.VideoWriter_fourcc(*'mp4v')
    out = cv2.VideoWriter(video_filename, fourcc, fps, (frame_width, frame_height))
    
    # Load face detector (if needed)
    if face_only:
        try:
            face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
        except Exception as e:
            print(f"Cannot load face detector: {e}")
            face_only = False
    
    # Writing progress
    frames_total = len(frames)
    
    # Process and write frames
    for i, frame in enumerate(frames):
        if i % 10 == 0:
            print(f"Processing frame {i+1}/{frames_total}...")
            
        # Detect faces but don't draw rectangles
        if face_only:
            try:
                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                faces = face_cascade.detectMultiScale(gray, 1.3, 5)
                
                # We don't draw face rectangles anymore
                # Just detect faces without drawing
            except Exception as e:
                print(f"Face detection error: {e}")
        
        # Add timestamp
        try:
            cv2.putText(frame, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 
                      (10, frame_height - 20), cv2.FONT_HERSHEY_SIMPLEX, 
                      0.5, (255, 255, 255), 1, cv2.LINE_AA)
        except Exception as e:
            print(f"Error adding timestamp: {e}")
        
        # Write to video
        out.write(frame)
    
    # Release resources
    out.release()
    cv2.destroyAllWindows()
    
    if len(frames) > 0:
        print(f"Video capture complete: {video_filename}")
        print(f"Total frames: {len(frames)}")
        
        # Create link to latest video
        if os.path.exists(latest_link):
            os.remove(latest_link)
        
        try:
            os.symlink(video_filename, latest_link)
        except (OSError, AttributeError):
            import shutil
            shutil.copy2(video_filename, latest_link)
        
        return video_filename
    else:
        print("No valid frames captured, video not saved")
        if os.path.exists(video_filename):
            os.remove(video_filename)
        return None

def test_server_connection(url):
    """Test server connection"""
    print(f"Testing server connection: {url}")
    
    try:
        session = requests.Session()
        session.verify = False
        
        # Set shorter timeout
        response = session.get(url, timeout=3, stream=True)
        
        if response.status_code == 200:
            print(f"Server connection successful! Status code: {response.status_code}")
            content_type = response.headers.get('content-type', '')
            print(f"Content type: {content_type}")
            
            # Close connection
            response.close()
            return True
        else:
            print(f"Server returned error status code: {response.status_code}")
            return False
    except Exception as e:
        print(f"Server connection test failed: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Fixed HTTPS Video Capture Tool")
    parser.add_argument("--url", default="http://172.20.10.7:5000/video_feed", 
                        help="Camera URL (supports HTTP and HTTPS)")
    parser.add_argument("--output", default="~/facial-payment-attack/media", 
                        help="Output directory")
    parser.add_argument("--duration", type=int, default=10, 
                        help="Capture duration (seconds)")
    parser.add_argument("--fps", type=int, default=25, 
                        help="Frame rate")
    parser.add_argument("--all-frames", action="store_true", 
                        help="Capture all frames")
    parser.add_argument("--https", action="store_true",
                        help="Force HTTPS URL (add https:// prefix)")
    parser.add_argument("--test", action="store_true",
                        help="Only test server connection")
    
    args = parser.parse_args()
    
    # Process URL
    url = args.url
    if args.https and not url.startswith('https://'):
        if url.startswith('http://'):
            url = 'https://' + url[7:]
        else:
            url = 'https://' + url
    
    print(f"Using URL: {url}")
    
    # Disable SSL certificate verification
    os.environ['PYTHONHTTPSVERIFY'] = '0'
    
    # Set OpenCV to ignore SSL certificate verification
    if hasattr(cv2, 'setNumThreads'):
        cv2.setNumThreads(4)  # Use multi-threading
    
    # If only testing connection
    if args.test:
        test_server_connection(url)
        return
    
    face_only = not args.all_frames
    capture_video(url, args.output, args.duration, args.fps, face_only)

if __name__ == "__main__":
    main()
