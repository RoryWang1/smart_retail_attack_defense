#!/usr/bin/env python3
import cv2
import time
import sys
import argparse
import ssl
import numpy as np
import os
import requests
from threading import Thread
import queue
import io
from PIL import Image
from datetime import datetime
import pytz

frame_queue = queue.Queue(maxsize=30)
running = True

def fetch_frames_thread(url):
    """Fetch video frames in a separate thread"""
    global running, frame_queue
    
    print(f"Starting video frame fetch thread: {url}")
    consecutive_failures = 0
    
    session = requests.Session()
    session.verify = False
    
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    
    while running:
        try:
            print("Attempting to connect...")
            response = session.get(url, stream=True, timeout=10)
            print(f"Connection status code: {response.status_code}")
            
            if response.status_code != 200:
                print(f"HTTP error status code: {response.status_code}")
                consecutive_failures += 1
                time.sleep(min(consecutive_failures, 5) * 0.5)
                continue
                
            print("Connected to HTTPS video stream")
            consecutive_failures = 0
            
            content_type = response.headers.get('content-type', '')
            print(f"Received Content-Type: {content_type}")
            if 'multipart/x-mixed-replace' not in content_type:
                print(f"Unsupported content type: {content_type}")
                consecutive_failures += 1
                time.sleep(1)
                continue
                
            boundary = content_type.split('boundary=')[1]
            boundary_str = f'--{boundary}'
            boundary_bytes = boundary_str.encode()
            print(f"Using boundary: {boundary_str}")
            
            buffer = bytes()
            print("Starting to read stream content...")
            frame_count = 0
            
            for chunk in response.iter_content(chunk_size=1024):
                if not running:
                    print("Running flag set to False, exiting chunk loop.")
                    break
                    
                if not chunk:
                    continue
                
                buffer += chunk
                
                while True:
                    # Look for frame start point
                    start_idx = buffer.find(boundary_bytes)
                    if start_idx == -1:
                        # Start point not found, wait for more data
                        break
                        
                    # After finding start point, look for next boundary (beginning of next frame)
                    next_idx = buffer.find(boundary_bytes, start_idx + len(boundary_bytes))
                    if next_idx == -1:
                        # End point not found, wait for more data
                        break
                    
                    # Extract a complete frame
                    frame_data = buffer[start_idx:next_idx]
                    
                    # Update buffer, keep the beginning part of the next frame
                    buffer = buffer[next_idx:]
                    
                    try:
                        # Look for marker that indicates JPEG data start (empty line after Content-Type)
                        jpeg_start = frame_data.find(b'\r\n\r\n')
                        if jpeg_start != -1:
                            jpeg_data = frame_data[jpeg_start + 4:]
                            
                            if len(jpeg_data) > 100:  # Simple size check
                                # Convert JPEG data to NumPy array
                                nparr = np.frombuffer(jpeg_data, np.uint8)
                                
                                # Decode image
                                img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
                                
                                if img is not None and img.size > 0:
                                    frame_count += 1
                                    
                                    if frame_queue.full():
                                        # Discard oldest frame when queue is full
                                        try:
                                            frame_queue.get_nowait()
                                        except queue.Empty:
                                            pass
                                    
                                    frame_queue.put(img)
                                else:
                                    print("cv2.imdecode failed or returned empty image.")
                    except Exception as e_parse:
                        print(f"Error parsing frame data: {e_parse}")
            
            print("Exited chunk reading loop.")

        except requests.exceptions.RequestException as e_req:
            print(f"Stream connection error: {e_req}")
            consecutive_failures += 1
            wait_time = min(consecutive_failures, 10) * 0.5
            print(f"Retrying in {wait_time:.1f} seconds...")
            time.sleep(wait_time)
        except Exception as e:
            print(f"Unhandled error in fetch_frames_thread: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()
            consecutive_failures += 1
            wait_time = min(consecutive_failures, 5) * 0.5
            print(f"Waiting {wait_time:.1f} seconds before retry...")
            time.sleep(wait_time)
    
    print("Fetch thread stopped.")

def get_london_time():
    """Get current time in London timezone"""
    london_tz = pytz.timezone('Europe/London')
    london_time = datetime.now(london_tz)
    return london_time.strftime("%Y-%m-%d %H:%M:%S")

def monitor_video_stream(url):
    """Display video stream"""
    global running, frame_queue
    
    print(f"Starting video stream monitoring: {url}")
    
    window_name = "HTTPS Video Stream Monitor"
    cv2.namedWindow(window_name, cv2.WINDOW_NORMAL)
    cv2.resizeWindow(window_name, 800, 600)
    
    fetch_thread = Thread(target=fetch_frames_thread, args=(url,))
    fetch_thread.daemon = True
    fetch_thread.start()
    
    consecutive_no_frames = 0
    last_frame = None
    frames_displayed = 0
    start_time = time.time()
    
    while running:
        try:
            try:
                frame = frame_queue.get(timeout=0.5)
                consecutive_no_frames = 0
                last_frame = frame.copy()
                
                # Create a mask for the bottom part of the image where timestamp might be
                height, width = frame.shape[:2]
                mask = np.ones((height, width, 3), dtype=np.uint8) * 255
                # Black out the bottom 40 pixels to cover any existing timestamp
                mask[height-40:height, :] = 0
                # Apply the mask (this will black out the bottom part)
                frame = cv2.bitwise_and(frame, mask)
                
                # Add London time in top-left corner
                london_time = get_london_time()
                cv2.putText(frame, london_time, (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 
                            0.7, (255, 255, 255), 2)
                
                # Add control hint to bottom right corner
                hint_text = "Press 'q' to quit | 'r' to reconnect"
                text_size = cv2.getTextSize(hint_text, cv2.FONT_HERSHEY_SIMPLEX, 0.5, 1)[0]
                text_x = frame.shape[1] - text_size[0] - 10
                text_y = frame.shape[0] - 10
                cv2.putText(frame, hint_text, (text_x, text_y), cv2.FONT_HERSHEY_SIMPLEX, 
                            0.5, (255, 255, 255), 1, cv2.LINE_AA)
                
                cv2.imshow(window_name, frame)
                frames_displayed += 1
                
            except queue.Empty:
                consecutive_no_frames += 1
                
                # If no frames received for a while but have a last frame, show it
                if last_frame is not None and consecutive_no_frames < 20:
                    status_frame = last_frame.copy()
                    cv2.putText(status_frame, "Waiting for new frames...", (status_frame.shape[1]//2 - 100, status_frame.shape[0]//2), 
                                cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 255), 2)
                    
                    # Add control hint to bottom right corner
                    hint_text = "Press 'q' to quit | 'r' to reconnect"
                    text_size = cv2.getTextSize(hint_text, cv2.FONT_HERSHEY_SIMPLEX, 0.5, 1)[0]
                    text_x = status_frame.shape[1] - text_size[0] - 10
                    text_y = status_frame.shape[0] - 10
                    cv2.putText(status_frame, hint_text, (text_x, text_y), cv2.FONT_HERSHEY_SIMPLEX, 
                                0.5, (255, 255, 255), 1, cv2.LINE_AA)
                    
                    cv2.imshow(window_name, status_frame)
                # If haven't received frames for a long time, show waiting message
                elif consecutive_no_frames >= 20:
                    waiting_frame = create_waiting_frame(f"Waiting for video stream... (attempt {consecutive_no_frames})")
                    cv2.imshow(window_name, waiting_frame)
            
            # Check if 'q' key pressed to exit
            key = cv2.waitKey(1) & 0xFF
            if key == ord('q'):
                print("User quit")
                running = False
                break
            elif key == ord('r'):
                print("User requested reconnection")
                # Restart fetch thread
                running = False
                time.sleep(0.5)
                running = True
                fetch_thread = Thread(target=fetch_frames_thread, args=(url,))
                fetch_thread.daemon = True
                fetch_thread.start()
                consecutive_no_frames = 0
                frames_displayed = 0
                start_time = time.time()
                
            # Brief pause to control display frame rate
            time.sleep(0.01)  
            
        except Exception as e:
            print(f"Error displaying frame: {e}")
            time.sleep(0.5)
    
    cv2.destroyAllWindows()

def create_waiting_frame(message):
    """Create a frame displaying a waiting message"""
    frame = np.zeros((480, 640, 3), dtype=np.uint8)
    
    cv2.putText(frame, message, (50, 240), cv2.FONT_HERSHEY_SIMPLEX, 
                1, (255, 255, 255), 2, cv2.LINE_AA)
    
    # Add London time to top-left corner
    london_time = get_london_time()
    cv2.putText(frame, london_time, (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 
                0.7, (255, 255, 255), 2)
    
    # Add control hint to bottom right corner
    hint_text = "Press 'q' to quit | 'r' to reconnect"
    text_size = cv2.getTextSize(hint_text, cv2.FONT_HERSHEY_SIMPLEX, 0.5, 1)[0]
    text_x = frame.shape[1] - text_size[0] - 10
    text_y = frame.shape[0] - 10
    cv2.putText(frame, hint_text, (text_x, text_y), cv2.FONT_HERSHEY_SIMPLEX, 
                0.5, (255, 255, 255), 1, cv2.LINE_AA)
    
    return frame

def main():
    parser = argparse.ArgumentParser(description="HTTPS Video Stream Monitoring Client")
    parser.add_argument("--url", default="https://192.168.164.128:5443/video_feed", 
                        help="Video stream URL")
    
    args = parser.parse_args()
    
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    os.environ['PYTHONHTTPSVERIFY'] = '0'
    
    try:
        monitor_video_stream(args.url)
    except KeyboardInterrupt:
        print("Program interrupted by user")
    finally:
        global running
        running = False
        cv2.destroyAllWindows()
        
if __name__ == "__main__":
    main()
