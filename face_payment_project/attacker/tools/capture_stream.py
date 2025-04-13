#!/usr/bin/env python3
# capture_stream.py - 从HTTPS摄像头服务器捕获视频流并保存
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

# 忽略SSL证书警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class StreamCapture:
    def __init__(self, stream_url, save_dir="media", interval=10, save_images=False, display=True):
        """
        初始化视频流捕获器
        :param stream_url: 视频流URL
        :param save_dir: 保存目录
        :param interval: 视频片段长度(秒)
        :param save_images: 是否保存图片
        :param display: 是否显示视频窗口
        """
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
        
        # 创建保存目录
        os.makedirs(os.path.join(self.save_dir, "videos"), exist_ok=True)
        if save_images:
            os.makedirs(os.path.join(self.save_dir, "images"), exist_ok=True)
        
        print(f"视频流捕获器已初始化")
        print(f"流URL: {stream_url}")
        print(f"保存目录: {save_dir}")
        print(f"视频片段长度: {interval}秒")
        print(f"保存图片: {'是' if save_images else '否'}")
        print(f"显示视频窗口: {'是' if display else '否'}")
    
    def create_new_video_writer(self):
        """创建新的视频写入器"""
        # 先删除已有的latest.mp4文件
        latest_path = os.path.join(self.save_dir, "videos", "latest.mp4")
        if os.path.exists(latest_path):
            try:
                os.remove(latest_path)
                print(f"已删除旧的latest.mp4文件")
            except Exception as e:
                print(f"删除旧的latest.mp4文件时出错: {e}")
        
        # 创建新的时间戳视频文件
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        video_path = os.path.join(self.save_dir, "videos", f"capture_{timestamp}.mp4")
        
        # 使用H.264编码器
        fourcc = cv2.VideoWriter_fourcc(*'avc1')  # 或使用'mp4v'
        writer = cv2.VideoWriter(video_path, fourcc, 20.0, (640, 480))
        
        if not writer.isOpened():
            print(f"无法创建视频文件: {video_path}")
            return None, None
        
        print(f"创建新视频文件: {video_path}")
        return writer, video_path
    
    def save_image(self, frame):
        """保存单帧图像"""
        if not self.save_images:
            return
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        image_path = os.path.join(self.save_dir, "images", f"frame_{timestamp}.jpg")
        cv2.imwrite(image_path, frame)
    
    def update_latest_video(self):
        """将当前视频复制为latest.mp4"""
        if self.current_video_path and os.path.exists(self.current_video_path):
            latest_path = os.path.join(self.save_dir, "videos", "latest.mp4")
            try:
                shutil.copy2(self.current_video_path, latest_path)
                print(f"已更新latest.mp4")
            except Exception as e:
                print(f"更新latest.mp4时出错: {e}")
    
    def capture_stream(self):
        """捕获视频流的主函数"""
        self.is_running = True
        start_time = time.time()
        
        # 创建初始视频写入器
        self.current_video_writer, self.current_video_path = self.create_new_video_writer()
        
        # 如果启用显示，创建窗口
        if self.display:
            window_name = "视频流捕获"
            cv2.namedWindow(window_name, cv2.WINDOW_NORMAL)
            cv2.resizeWindow(window_name, 640, 480)
        
        try:
            # 使用requests以流的方式获取数据
            response = requests.get(self.stream_url, stream=True, verify=False)
            if response.status_code != 200:
                print(f"连接失败，状态码: {response.status_code}")
                return
            
            print("成功连接到视频流，开始捕获...")
            
            # 处理multipart/x-mixed-replace类型的流
            boundary = b'--frame'
            frame_data = b''
            
            for chunk in response.iter_content(chunk_size=1024):
                if not self.is_running:
                    break
                
                frame_data += chunk
                frame_start = frame_data.find(b'\r\n\r\n')
                
                # 如果找到了帧开始标记，并且帧数据足够大
                if frame_start != -1 and len(frame_data) > frame_start + 4:
                    # 提取图像数据
                    image_data = frame_data[frame_start+4:]
                    # 寻找下一个边界的位置
                    boundary_pos = image_data.find(boundary)
                    
                    if boundary_pos != -1:
                        # 提取完整的JPEG数据
                        jpeg_data = image_data[:boundary_pos]
                        
                        try:
                            # 将JPEG数据转换为图像
                            nparr = np.frombuffer(jpeg_data, np.uint8)
                            frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
                            
                            if frame is not None:
                                # 保存为视频
                                if self.current_video_writer is not None:
                                    self.current_video_writer.write(frame)
                                    self.frame_count += 1
                                
                                # 保存为图像（如果启用）
                                self.save_image(frame)
                                
                                # 显示视频帧（如果启用）
                                if self.display:
                                    # 在帧上添加时间信息和状态
                                    time_left = max(0, self.interval - (time.time() - start_time))
                                    status_text = f"录制中: {time_left:.1f}秒剩余"
                                    cv2.putText(frame, status_text, (10, 30), 
                                                cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0), 2)
                                    
                                    cv2.imshow(window_name, frame)
                                    # 处理键盘事件 (按ESC键退出)
                                    key = cv2.waitKey(1) & 0xFF
                                    if key == 27:  # ESC键
                                        print("用户按下ESC键，停止捕获")
                                        self.is_running = False
                                        break
                                
                                # 检查是否需要创建新的视频片段
                                current_time = time.time()
                                if current_time - start_time >= self.interval:
                                    if self.current_video_writer is not None:
                                        self.current_video_writer.release()
                                        print(f"已完成视频片段: {self.current_video_path} (帧数: {self.frame_count})")
                                        
                                        # 更新latest.mp4
                                        self.update_latest_video()
                                        self.completed = True
                                        
                                        # 一个视频后退出程序
                                        print("录制完成一个视频片段，程序将退出")
                                        self.is_running = False
                                        break
                        except Exception as e:
                            print(f"处理帧时出错: {e}")
                        
                        # 清理,保留边界之后的数据用于下一帧
                        frame_data = image_data[boundary_pos:]
                
        except Exception as e:
            print(f"捕获流时出错: {e}")
        finally:
            if self.current_video_writer is not None:
                self.current_video_writer.release()
                if not self.completed:
                    print(f"已完成视频片段: {self.current_video_path}")
                    # 最后一次更新latest.mp4
                    self.update_latest_video()
            
            # 关闭显示窗口
            if self.display:
                cv2.destroyAllWindows()
            
            self.is_running = False

def main():
    parser = argparse.ArgumentParser(description='从HTTPS摄像头服务器捕获视频流')
    parser.add_argument('url', help='视频流URL')
    parser.add_argument('--save-dir', '-d', default='media', help='保存目录')
    parser.add_argument('--interval', '-i', type=int, default=10, help='视频片段长度(秒)')
    parser.add_argument('--no-images', action='store_true', help='不保存图像，仅保存视频')
    parser.add_argument('--no-display', action='store_true', help='不显示视频窗口')
    args = parser.parse_args()
    
    print("=" * 50)
    print("HTTPS视频流捕获工具")
    print("=" * 50)
    
    try:
        # 创建捕获器
        capturer = StreamCapture(
            args.url,
            save_dir=args.save_dir,
            interval=args.interval,
            save_images=not args.no_images,
            display=not args.no_display
        )
        
        # 直接在主线程中运行捕获，不再使用线程
        capturer.capture_stream()
        
        print("捕获已完成。")
        
    except Exception as e:
        print(f"程序出错: {e}")
    
    sys.exit(0)

if __name__ == "__main__":
    main()
