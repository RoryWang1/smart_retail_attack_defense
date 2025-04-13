#!/usr/bin/env python3
# 极简稳定版 HTTPS 摄像头服务器
# 使用最基本的OpenCV功能和错误处理

from flask import Flask, Response
import cv2
import time
import os
import socket
import numpy as np
import threading
import subprocess
import logging

# 配置日志
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

# 全局变量
camera = None
camera_lock = threading.Lock()
FALLBACK_MODE = False  # 当摄像头不可用时启用备用模式

# 创建一个蓝色的"摄像头不可用"静态图像作为备用
def create_fallback_image():
    img = np.zeros((480, 640, 3), dtype=np.uint8)
    img[:, :] = (255, 0, 0)  # 蓝色背景
    font = cv2.FONT_HERSHEY_SIMPLEX
    cv2.putText(img, "CAMERA UNAVAILABLE", (100, 240), font, 1, (255, 255, 255), 2)
    cv2.putText(img, "Server running in fallback mode", (80, 280), font, 0.7, (255, 255, 255), 1)
    return img

# 初始化备用图像
FALLBACK_IMAGE = create_fallback_image()

def safe_get_camera():
    """安全地获取摄像头实例"""
    global camera, FALLBACK_MODE
    
    with camera_lock:
        if camera is None:
            logger.info("正在初始化摄像头...")
            try:
                # 使用最简单的摄像头初始化方式
                camera = cv2.VideoCapture(0)
                if not camera.isOpened():
                    logger.error("摄像头无法打开，切换到备用模式")
                    FALLBACK_MODE = True
                    return None
                else:
                    logger.info("摄像头已成功初始化")
                    FALLBACK_MODE = False
            except Exception as e:
                logger.error(f"摄像头初始化错误: {e}")
                FALLBACK_MODE = True
                return None
        return camera

def safe_release_camera():
    """安全地释放摄像头"""
    global camera
    with camera_lock:
        if camera is not None:
            try:
                camera.release()
                logger.info("摄像头已释放")
            except Exception as e:
                logger.error(f"释放摄像头出错: {e}")
            camera = None

def generate_frames():
    """生成视频帧的生成器函数"""
    global FALLBACK_MODE, FALLBACK_IMAGE
    
    # 每5次失败尝试重新打开一次摄像头
    failure_count = 0
    max_consecutive_failures = 5
    frame_count = 0
    
    logger.info("开始生成视频帧")
    
    try:
        while True:
            # 检查当前是否处于备用模式
            if FALLBACK_MODE:
                # 使用备用静态图像，但添加时间戳让其有变化
                img = FALLBACK_IMAGE.copy()
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                cv2.putText(img, timestamp, (10, 460), cv2.FONT_HERSHEY_SIMPLEX, 
                            0.7, (255, 255, 255), 1)
                
                # 每30帧尝试一次恢复摄像头
                if frame_count % 30 == 0:
                    logger.info("尝试恢复摄像头...")
                    safe_release_camera()  # 释放现有实例
                    if safe_get_camera() is not None:
                        FALLBACK_MODE = False
                        logger.info("摄像头已恢复")
                
                # 编码并发送静态图像
                ret, buffer = cv2.imencode('.jpg', img)
                if not ret:
                    logger.warning("静态图像编码失败")
                    time.sleep(0.1)
                    continue
                
                frame_bytes = buffer.tobytes()
                
                # 返回一帧
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')
                
                # 控制帧率
                time.sleep(0.1)  # 约10fps，备用模式下降低帧率节省资源
                frame_count += 1
                continue
            
            # 正常模式：尝试获取摄像头
            cam = safe_get_camera()
            if cam is None:
                FALLBACK_MODE = True
                continue
            
            # 尝试读取帧
            success = False
            try:
                with camera_lock:
                    success, frame = cam.read()
            except Exception as e:
                logger.error(f"读取摄像头帧出错: {e}")
                success = False
            
            # 处理读取失败情况
            if not success:
                failure_count += 1
                logger.warning(f"读取摄像头帧失败 ({failure_count}/{max_consecutive_failures})")
                
                if failure_count >= max_consecutive_failures:
                    logger.error("连续读取失败，切换到备用模式")
                    FALLBACK_MODE = True
                    failure_count = 0
                
                time.sleep(0.1)
                continue
            
            # 成功读取后重置失败计数
            failure_count = 0
            
            # 编码并发送真实摄像头帧
            try:
                ret, buffer = cv2.imencode('.jpg', frame)
                if not ret:
                    logger.warning("编码失败")
                    time.sleep(0.1)
                    continue
                
                frame_bytes = buffer.tobytes()
                
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')
                
                # 控制帧率
                time.sleep(0.04)  # 约25fps
                frame_count += 1
            except Exception as e:
                logger.error(f"处理帧时出错: {e}")
                time.sleep(0.1)
                
    except GeneratorExit:
        logger.info("视频流生成器已关闭（客户端断开连接）")
    except Exception as e:
        logger.error(f"视频流生成器严重错误: {e}")
    finally:
        logger.info("视频流生成器结束")

@app.route('/')
def index():
    """首页，显示视频流"""
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
    """视频流端点"""
    try:
        return Response(generate_frames(),
                       mimetype='multipart/x-mixed-replace; boundary=frame',
                       headers={
                           'Cache-Control': 'no-cache, private',
                           'Pragma': 'no-cache',
                           'Expires': '0'
                       })
    except Exception as e:
        logger.error(f"创建视频流响应出错: {e}")
        return "Video stream error", 500

@app.route('/status')
def status():
    """服务器状态端点"""
    global FALLBACK_MODE
    return {
        "status": "running", 
        "mode": "fallback" if FALLBACK_MODE else "normal",
        "time": time.strftime("%Y-%m-%d %H:%M:%S")
    }

@app.errorhandler(Exception)
def handle_error(e):
    """全局错误处理器"""
    logger.error(f"请求处理错误: {e}")
    return "Server error", 500

def generate_ssl_cert():
    """生成自签名SSL证书"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    cert_dir = os.path.join(script_dir, "certs")
    os.makedirs(cert_dir, exist_ok=True)
    
    cert_file = os.path.join(cert_dir, "cert.pem")
    key_file = os.path.join(cert_dir, "key.pem")
    
    if os.path.exists(cert_file) and os.path.exists(key_file):
        logger.info("使用现有SSL证书")
        return cert_file, key_file
    
    logger.info("生成新的SSL证书...")
    
    try:
        from OpenSSL import crypto
    except ImportError:
        logger.error("缺少pyopenssl，请安装: pip install pyopenssl")
        exit(1)
    
    # 创建密钥
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)
    
    # 创建证书
    cert = crypto.X509()
    cert.get_subject().C = "CN"
    cert.get_subject().ST = "State"
    cert.get_subject().L = "City"
    cert.get_subject().O = "Organization"
    cert.get_subject().CN = socket.gethostname()
    
    # 设置序列号和有效期
    import random
    cert.set_serial_number(random.randint(0, 2**64-1))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)  # 一年有效期
    
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha256')
    
    # 写入文件
    with open(cert_file, "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    
    with open(key_file, "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
    
    logger.info(f"SSL证书已保存至: {cert_dir}")
    return cert_file, key_file

def cleanup():
    """退出时的清理函数"""
    logger.info("程序退出，正在清理资源...")
    safe_release_camera()

if __name__ == '__main__':
    # 注册退出清理函数
    import atexit
    atexit.register(cleanup)
    
    # 生成SSL证书
    cert_file, key_file = generate_ssl_cert()
    
    # 服务器配置
    logger.info("正在启动摄像头服务器...")
    logger.info(f"服务器将在 0.0.0.0:5443 监听")
    
    # 启动服务器
    try:
        app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
        app.config['PROPAGATE_EXCEPTIONS'] = False
        
        app.run(host='0.0.0.0', 
                port=5443, 
                ssl_context=(cert_file, key_file),
                threaded=True,
                debug=False)
    except Exception as e:
        logger.error(f"服务器启动错误: {e}")
    finally:
        cleanup()
