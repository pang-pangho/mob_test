"""
유틸리티 함수들
공통으로 사용되는 함수들을 모아둔 모듈
"""

import os
import logging
from pathlib import Path
from datetime import datetime

def setup_logging(log_level=logging.INFO):
    """
    로깅 설정
    
    Args:
        log_level: 로그 레벨
        
    Returns:
        logger: 설정된 로거
    """
    # 로그 디렉토리 생성
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    # 로그 파일명 생성
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"mobsf_analyzer_{timestamp}.log"
    
    # 로깅 설정
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(str(log_file), encoding='utf-8'),
            logging.StreamHandler()
        ]
    )
    
    logger = logging.getLogger('MyMobSF_Analyzer')
    logger.info("로깅 시스템 초기화 완료")
    
    return logger

def print_banner():
    """프로그램 시작 배너 출력"""
    banner = """
████████████████████████████████████████████████████████████████████████████████
█                                                                              █
█    ███╗   ███╗██╗   ██╗███╗   ███╗ ██████╗ ██████╗ ███████╗███████╗         █
█    ████╗ ████║╚██╗ ██╔╝████╗ ████║██╔═══██╗██╔══██╗██╔════╝██╔════╝         █
█    ██╔████╔██║ ╚████╔╝ ██╔████╔██║██║   ██║██████╔╝███████╗█████╗           █
█    ██║╚██╔╝██║  ╚██╔╝  ██║╚██╔╝██║██║   ██║██╔══██╗╚════██║██╔══╝           █
█    ██║ ╚═╝ ██║   ██║   ██║ ╚═╝ ██║╚██████╔╝██████╔╝███████║██║              █
█    ╚═╝     ╚═╝   ╚═╝   ╚═╝     ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝              █
█                                                                              █
█                        모바일 보안 분석 자동화 도구                           █
█                             Analyzer v2.0                                   █
█                                                                              █
████████████████████████████████████████████████████████████████████████████████
"""
    print(banner)

def get_apk_files(directory):
    """
    디렉토리에서 APK 파일 목록 반환
    
    Args:
        directory (str): 검색할 디렉토리
        
    Returns:
        list: APK 파일 경로 목록
    """
    apk_files = []
    directory_path = Path(directory)
    
    if directory_path.exists():
        for file_path in directory_path.glob("*.apk"):
            if file_path.is_file():
                apk_files.append(file_path)
    
    return sorted(apk_files)

def validate_file_path(file_path):
    """
    파일 경로 유효성 검사
    
    Args:
        file_path (str): 검사할 파일 경로
        
    Returns:
        bool: 유효한 경우 True
    """
    path = Path(file_path)
    return path.exists() and path.is_file()

def format_file_size(size_bytes):
    """
    파일 크기를 읽기 쉬운 형태로 변환
    
    Args:
        size_bytes (int): 바이트 크기
        
    Returns:
        str: 포맷된 크기 문자열
    """
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB"]
    i = 0
    
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.1f} {size_names[i]}"

def get_timestamp():
    """현재 타임스탬프 반환"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def create_directory_if_not_exists(directory_path):
    """디렉토리가 없으면 생성"""
    path = Path(directory_path)
    path.mkdir(parents=True, exist_ok=True)
    return path

def safe_filename(filename):
    """
    안전한 파일명 생성 (특수문자 제거)
    
    Args:
        filename (str): 원본 파일명
        
    Returns:
        str: 안전한 파일명
    """
    import re
    # 특수문자를 언더스코어로 대체
    safe_name = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # 연속된 언더스코어는 하나로 줄임
    safe_name = re.sub(r'_+', '_', safe_name)
    # 앞뒤 언더스코어 제거
    safe_name = safe_name.strip('_')
    
    return safe_name if safe_name else "unnamed_file"

def read_config_value(config, section, key, default=None):
    """
    설정 값 안전하게 읽기
    
    Args:
        config: 설정 객체
        section (str): 섹션명
        key (str): 키명
        default: 기본값
        
    Returns:
        설정 값 또는 기본값
    """
    try:
        return config.get(section, key)
    except:
        return default

def is_valid_apk_file(file_path):
    """
    유효한 APK 파일인지 확인
    
    Args:
        file_path (str): 파일 경로
        
    Returns:
        bool: APK 파일이면 True
    """
    try:
        import zipfile
        
        if not validate_file_path(file_path):
            return False
        
        # APK는 ZIP 파일이므로, ZIP으로 열어볼 수 있는지 확인
        with zipfile.ZipFile(file_path, 'r') as zip_file:
            # AndroidManifest.xml이 있는지 확인
            return 'AndroidManifest.xml' in zip_file.namelist()
    
    except:
        return False

def cleanup_temp_files(temp_dir):
    """임시 파일 정리"""
    try:
        import shutil
        temp_path = Path(temp_dir)
        if temp_path.exists():
            shutil.rmtree(temp_path)
            return True
    except:
        pass
    return False
