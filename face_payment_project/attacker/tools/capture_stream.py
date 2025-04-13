#!/usr/bin/env python3
import cv2
import numpy as np
import requests
import os
import time
import argparse
import threading
import urllib3
from datetime import datetime
import shutil
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class StreamCapture:
    def __init__(self, stream_url, save_dir="media", interval=10, save_images=False, display=True):
        """Stream capture initialization"""
        self.stream_url = stream_url
        self.save_dir = save_dir
        self.interval = interval
        self.save_images = save_images
        self.display = display
        self.is_running = False
        self.current_video_writer = None
        self.current_video_path = None
        self.frame_count = 0
        self.completed = False
        
        os.makedirs(os.path.join(self.save_dir, "videos"), exist_ok=True)
        if save_images:
            os.makedirs(os.path.join(self.save_dir, "images"), exist_ok=True)
        
        print(f"Video stream capturer initialized")
        print(f"Stream URL: {stream_url}")
        print(f"Save directory: {save_dir}")
        print(f"Video clip length: {interval} seconds")
        print(f"Save images: {'Yes' if save_images else 'No'}")
        print(f"Display video window: {'Yes' if display else 'No'}")
    
    def create_new_video_writer(self):
        """Create new video writer"""
        latest_path = os.path.join(self.save_dir, "videos", "latest.mp4")
        if os.path.exists(latest_path):
            try:
                os.remove(latest_path)
                print(f"Deleted old latest.mp4 file")
            except Exception as e:
                print(f"Error deleting old latest.mp4 file: {e}")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        video_path = os.path.join(self.save_dir, "videos", f"capture_{timestamp}.mp4")
        
        fourcc = cv2.VideoWriter_fourcc(*'avc1')  # or use 'mp4v'
        writer = cv2.VideoWriter(video_path, fourcc, 20.0, (640, 480))
        
        if not writer.isOpened():
            print(f"Unable to create video file: {video_path}")
            return None, None
        
        print(f"Created new video file: {video_path}")
        return writer, video_path
    
    def save_image(self, frame):
        """Save single frame image"""
        if not self.save_images:
            return
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        image_path = os.path.join(self.save_dir, "images", f"frame_{timestamp}.jpg")
        cv2.imwrite(image_path, frame)
    
    def update_latest_video(self):
        """Copy current video as latest.mp4"""
        if self.current_video_path and os.path.exists(self.current_video_path):
            latest_path = os.path.join(self.save_dir, "videos", "latest.mp4")
            try:
                shutil.copy2(self.current_video_path, latest_path)
                print(f"Updated latest.mp4")
            except Exception as e:
                print(f"Error updating latest.mp4: {e}")
    
    def capture_stream(self):
        """Main function to capture video stream"""
        self.is_running = True
        start_time = time.time()
        
        self.current_video_writer, self.current_video_path = self.create_new_video_writer()
        
        if self.display:
            window_name = "Video Stream Capture"
            cv2.namedWindow(window_name, cv2.WINDOW_NORMAL)
            cv2.resizeWindow(window_name, 640, 480)
        
        try:
            response = requests.get(self.stream_url, stream=True, verify=False)
            if response.status_code != 200:
                print(f"Connection failed, status code: {response.status_code}")
                return
            
            print("Successfully connected to video stream, starting capture...")
            
            boundary = b'--frame'
            frame_data = b''
            
            for chunk in response.iter_content(chunk_size=1024):
                if not self.is_running:
                    break
                
                frame_data += chunk
                frame_start = frame_data.find(b'\r\n\r\n')
                
                if frame_start != -1 and len(frame_data) > frame_start + 4:
                    image_data = frame_data[frame_start+4:]
                    boundary_pos = image_data.find(boundary)
                    
                    if boundary_pos != -1:
                        jpeg_data = image_data[:boundary_pos]
                        
                        try:
                            nparr = np.frombuffer(jpeg_data, np.uint8)
                            frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
                            
                            if frame is not None:
                                if self.current_video_writer is not None:
                                    self.current_video_writer.write(frame)
                                    self.frame_count += 1
                                
                                self.save_image(frame)
                                
                                if self.display:
                                    time_left = max(0, self.interval - (time.time() - start_time))
                                    status_text = f"Recording: {time_left:.1f} seconds remaining"
                                    cv2.putText(frame, status_text, (10, 30), 
                                                cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0), 2)
                                    
                                    cv2.imshow(window_name, frame)
                                    key = cv2.waitKey(1) & 0xFF
                                    if key == 27:  # ESC key
                                        print("User pressed ESC key, stopping capture")
                                        self.is_running = False
                                        break
                                
                                current_time = time.time()
                                if current_time - start_time >= self.interval:
                                    if self.current_video_writer is not None:
                                        self.current_video_writer.release()
                                        print(f"Completed video clip: {self.current_video_path} (frames: {self.frame_count})")
                                        
                                        self.update_latest_video()
                                        self.completed = True
                                        
                                        print("Recording completed one video clip, program will exit")
                                        self.is_running = False
                                        break
                        except Exception as e:
                            print(f"Error processing frame: {e}")
                        
                        frame_data = image_data[boundary_pos:]
                
        except Exception as e:
            print(f"Error capturing stream: {e}")
        finally:
            if self.current_video_writer is not None:
                self.current_video_writer.release()
                if not self.completed:
                    print(f"Completed video clip: {self.current_video_path}")
                    self.update_latest_video()
            
            if self.display:
                cv2.destroyAllWindows()
            
            self.is_running = False

def main():
    parser = argparse.ArgumentParser(description='Capture video stream from HTTPS camera server')
    parser.add_argument('url', help='Video stream URL')
    parser.add_argument('--save-dir', '-d', default='media', help='Save directory')
    parser.add_argument('--interval', '-i', type=int, default=10, help='Video clip length (seconds)')
    parser.add_argument('--no-images', action='store_true', help='Do not save images, only save video')
    parser.add_argument('--no-display', action='store_true', help='Do not display video window')
    args = parser.parse_args()
    
    print("=" * 50)
    print("HTTPS Video Stream Capture Tool")
    print("=" * 50)
    
    try:
        capturer = StreamCapture(
            args.url,
            save_dir=args.save_dir,
            interval=args.interval,
            save_images=not args.no_images,
            display=not args.no_display
        )
        
        capturer.capture_stream()
        
        print("Capture completed.")
        
    except Exception as e:
        print(f"Program error: {e}")
    
    sys.exit(0)

if __name__ == "__main__":
    main()
