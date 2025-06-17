"""
MobSF REST API 클라이언트
MobSF 서버와의 모든 통신을 담당하는 클래스
"""

import os
import json
import time
import requests
from pathlib import Path
from requests_toolbelt.multipart.encoder import MultipartEncoder
import logging

class MobSFAPI:
    """MobSF REST API 클라이언트 클래스"""
    
    def __init__(self, server_ip, api_key):
        """
        MobSF API 클라이언트 초기화
        
        Args:
            server_ip (str): MobSF 서버 주소
            api_key (str): API 키
        """
        self.server_ip = server_ip.rstrip('/')
        self.api_key = api_key
        self.headers = {'Authorization': api_key}
        self.logger = logging.getLogger(__name__)
        self.current_hash = None
        
    def check_server_status(self):
        """서버 상태 확인"""
        try:
            response = requests.get(f"{self.server_ip}/", timeout=10)
            return response.status_code == 200
        except requests.exceptions.RequestException as e:
            self.logger.error(f"서버 연결 실패: {str(e)}")
            return False
    
    def upload_file(self, file_path):
        """
        파일 업로드
        
        Args:
            file_path (str): 업로드할 파일 경로
            
        Returns:
            dict: 업로드 결과 (hash 포함)
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"파일을 찾을 수 없습니다: {file_path}")
        
        self.logger.info(f"파일 업로드 시작: {file_path}")
        
        try:
            with open(file_path, 'rb') as f:
                multipart_data = MultipartEncoder(
                    fields={'file': (os.path.basename(file_path), f, 'application/octet-stream')}
                )
                
                headers = {
                    'Content-Type': multipart_data.content_type,
                    'Authorization': self.api_key
                }
                
                response = requests.post(
                    f"{self.server_ip}/api/v1/upload",
                    data=multipart_data,
                    headers=headers,
                    timeout=300
                )
                
                if response.status_code == 200:
                    result = response.json()
                    self.current_hash = result.get('hash')
                    self.logger.info(f"파일 업로드 성공: {self.current_hash}")
                    return result
                else:
                    self.logger.error(f"업로드 실패: {response.status_code} - {response.text}")
                    return None
                    
        except Exception as e:
            self.logger.error(f"업로드 중 오류 발생: {str(e)}")
            return None
    
    def scan_file(self, file_hash=None, rescan=False):
        """
        파일 스캔 실행
        
        Args:
            file_hash (str): 스캔할 파일의 해시값
            rescan (bool): 재스캔 여부
            
        Returns:
            dict: 스캔 결과
        """
        if not file_hash and not self.current_hash:
            raise ValueError("파일 해시가 필요합니다")
        
        hash_value = file_hash or self.current_hash
        self.logger.info(f"파일 스캔 시작: {hash_value}")
        
        try:
            data = {
                'hash': hash_value,
                'rescan': '1' if rescan else '0'
            }
            
            response = requests.post(
                f"{self.server_ip}/api/v1/scan",
                data=data,
                headers=self.headers,
                timeout=600
            )
            
            if response.status_code == 200:
                self.logger.info("파일 스캔 완료")
                return response.json()
            else:
                self.logger.error(f"스캔 실패: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            self.logger.error(f"스캔 중 오류 발생: {str(e)}")
            return None
    
    def get_json_report(self, file_hash=None):
        """
        JSON 리포트 생성
        
        Args:
            file_hash (str): 리포트 생성할 파일의 해시값
            
        Returns:
            dict: JSON 리포트 데이터
        """
        hash_value = file_hash or self.current_hash
        if not hash_value:
            raise ValueError("파일 해시가 필요합니다")
        
        self.logger.info(f"JSON 리포트 생성: {hash_value}")
        
        try:
            data = {'hash': hash_value}
            response = requests.post(
                f"{self.server_ip}/api/v1/report_json",
                data=data,
                headers=self.headers,
                timeout=300
            )
            
            if response.status_code == 200:
                self.logger.info("JSON 리포트 생성 완료")
                return response.json()
            else:
                self.logger.error(f"JSON 리포트 생성 실패: {response.status_code}")
                return None
                
        except Exception as e:
            self.logger.error(f"JSON 리포트 생성 중 오류: {str(e)}")
            return None
    
    def download_pdf_report(self, file_hash=None, output_path=None):
        """
        PDF 리포트 다운로드
        
        Args:
            file_hash (str): 리포트 다운로드할 파일의 해시값
            output_path (str): 저장할 경로
            
        Returns:
            str: 저장된 파일 경로
        """
        hash_value = file_hash or self.current_hash
        if not hash_value:
            raise ValueError("파일 해시가 필요합니다")
        
        if not output_path:
            output_path = f"reports/{hash_value}_report.pdf"
        
        self.logger.info(f"PDF 리포트 다운로드: {hash_value}")
        
        try:
            data = {'hash': hash_value}
            response = requests.post(
                f"{self.server_ip}/api/v1/download_pdf",
                data=data,
                headers=self.headers,
                timeout=300,
                stream=True
            )
            
            if response.status_code == 200:
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                
                with open(output_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=1024):
                        if chunk:
                            f.write(chunk)
                
                self.logger.info(f"PDF 리포트 저장 완료: {output_path}")
                return output_path
            else:
                self.logger.error(f"PDF 다운로드 실패: {response.status_code}")
                return None
                
        except Exception as e:
            self.logger.error(f"PDF 다운로드 중 오류: {str(e)}")
            return None
    
    def start_dynamic_analysis(self, file_hash=None):
        """동적 분석 시작"""
        hash_value = file_hash or self.current_hash
        if not hash_value:
            raise ValueError("파일 해시가 필요합니다")
        
        self.logger.info(f"동적 분석 시작: {hash_value}")
        
        try:
            data = {'hash': hash_value}
            response = requests.post(
                f"{self.server_ip}/api/v1/dynamic/start_analysis",
                data=data,
                headers=self.headers,
                timeout=300
            )
            
            if response.status_code == 200:
                self.logger.info("동적 분석 시작됨")
                return response.json()
            else:
                self.logger.error(f"동적 분석 시작 실패: {response.status_code}")
                return None
                
        except Exception as e:
            self.logger.error(f"동적 분석 시작 중 오류: {str(e)}")
            return None
    
    def stop_dynamic_analysis(self, file_hash=None):
        """동적 분석 중지"""
        hash_value = file_hash or self.current_hash
        if not hash_value:
            raise ValueError("파일 해시가 필요합니다")
        
        self.logger.info(f"동적 분석 중지: {hash_value}")
        
        try:
            data = {'hash': hash_value}
            response = requests.post(
                f"{self.server_ip}/api/v1/dynamic/stop_analysis",
                data=data,
                headers=self.headers,
                timeout=60
            )
            
            if response.status_code == 200:
                self.logger.info("동적 분석 중지됨")
                return response.json()
            else:
                self.logger.error(f"동적 분석 중지 실패: {response.status_code}")
                return None
                
        except Exception as e:
            self.logger.error(f"동적 분석 중지 중 오류: {str(e)}")
            return None
    
    def get_recent_scans(self, page=1, page_size=10):
        """최근 스캔 목록 조회"""
        try:
            params = {'page': page, 'page_size': page_size}
            response = requests.get(
                f"{self.server_ip}/api/v1/scans",
                params=params,
                headers=self.headers,
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                self.logger.error(f"스캔 목록 조회 실패: {response.status_code}")
                return None
                
        except Exception as e:
            self.logger.error(f"스캔 목록 조회 중 오류: {str(e)}")
            return None
    
    def delete_scan(self, file_hash):
        """스캔 결과 삭제"""
        try:
            data = {'hash': file_hash}
            response = requests.post(
                f"{self.server_ip}/api/v1/delete_scan",
                data=data,
                headers=self.headers,
                timeout=30
            )
            
            if response.status_code == 200:
                self.logger.info(f"스캔 결과 삭제 완료: {file_hash}")
                return response.json()
            else:
                self.logger.error(f"스캔 삭제 실패: {response.status_code}")
                return None
                
        except Exception as e:
            self.logger.error(f"스캔 삭제 중 오류: {str(e)}")
            return None
