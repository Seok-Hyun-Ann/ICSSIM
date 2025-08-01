import os
import json
import time
import threading
from datetime import datetime, timedelta

class ConfigLockManager:
    """
    HMI 간의 설정 변경 권한을 제어하는 락 매니저
    하나의 HMI에서만 설정 변경이 가능하도록 제어
    """
    
    def __init__(self, lock_file_path='storage/config_lock.json', timeout_minutes=10):
        self.lock_file_path = lock_file_path
        self.timeout_minutes = timeout_minutes
        self.lock = threading.Lock()
        
        # 저장 디렉토리 생성
        os.makedirs(os.path.dirname(lock_file_path), exist_ok=True)
        
    def acquire_lock(self, hmi_name):
        """
        설정 변경 권한을 획득합니다.
        
        Args:
            hmi_name (str): HMI 이름 (HMI1, HMI2)
            
        Returns:
            bool: 권한 획득 성공 여부
        """
        with self.lock:
            current_lock = self._read_lock_file()
            
            # 기존 락이 없거나 만료된 경우
            if not current_lock or self._is_lock_expired(current_lock):
                self._write_lock_file(hmi_name)
                return True
            
            # 같은 HMI가 이미 락을 보유한 경우
            if current_lock.get('hmi_name') == hmi_name:
                # 락 시간 갱신
                self._write_lock_file(hmi_name)
                return True
            
            # 다른 HMI가 락을 보유한 경우
            return False
    
    def release_lock(self, hmi_name):
        """
        설정 변경 권한을 해제합니다.
        
        Args:
            hmi_name (str): HMI 이름 (HMI1, HMI2)
            
        Returns:
            bool: 권한 해제 성공 여부
        """
        with self.lock:
            current_lock = self._read_lock_file()
            
            if current_lock and current_lock.get('hmi_name') == hmi_name:
                self._clear_lock_file()
                return True
            
            return False
    
    def get_lock_status(self):
        """
        현재 락 상태를 반환합니다.
        
        Returns:
            dict: 락 상태 정보
        """
        with self.lock:
            current_lock = self._read_lock_file()
            
            if not current_lock:
                return {'locked': False, 'hmi_name': None, 'expires_at': None}
            
            if self._is_lock_expired(current_lock):
                self._clear_lock_file()
                return {'locked': False, 'hmi_name': None, 'expires_at': None}
            
            return {
                'locked': True,
                'hmi_name': current_lock['hmi_name'],
                'expires_at': current_lock['expires_at']
            }
    
    def _read_lock_file(self):
        """락 파일을 읽습니다."""
        try:
            if os.path.exists(self.lock_file_path):
                with open(self.lock_file_path, 'r') as f:
                    return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
        return None
    
    def _write_lock_file(self, hmi_name):
        """락 파일을 작성합니다."""
        lock_data = {
            'hmi_name': hmi_name,
            'timestamp': datetime.now().isoformat(),
            'expires_at': (datetime.now() + timedelta(minutes=self.timeout_minutes)).isoformat()
        }
        
        try:
            with open(self.lock_file_path, 'w') as f:
                json.dump(lock_data, f, indent=2)
        except IOError:
            pass
    
    def _clear_lock_file(self):
        """락 파일을 삭제합니다."""
        try:
            if os.path.exists(self.lock_file_path):
                os.remove(self.lock_file_path)
        except IOError:
            pass
    
    def _is_lock_expired(self, lock_data):
        """락이 만료되었는지 확인합니다."""
        try:
            expires_at = datetime.fromisoformat(lock_data['expires_at'])
            return datetime.now() > expires_at
        except (KeyError, ValueError):
            return True

# 전역 락 매니저 인스턴스
config_lock_manager = ConfigLockManager()