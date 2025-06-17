#!/usr/bin/env python3
"""
MyMobSF_Analyzer - 모바일 보안 분석 도구
사용자 맞춤형 MobSF 자동화 분석 시스템
"""

import os
import sys
import configparser
from pathlib import Path
from src.app_analyzer import AppAnalyzer
from src.utils import setup_logging, print_banner

def main():
    """메인 실행 함수"""
    print_banner()
    
    # 로깅 설정
    logger = setup_logging()
    logger.info("MyMobSF_Analyzer 시작")
    
    try:
        # 설정 파일 로드
        config_path = Path("config/config.ini")
        if not config_path.exists():
            logger.error("설정 파일을 찾을 수 없습니다: config/config.ini")
            sys.exit(1)
        
        config = configparser.ConfigParser()
        config.read(config_path, encoding='utf-8')
        
        # 앱 분석기 초기화
        analyzer = AppAnalyzer(config)
        
        # 명령행 인터페이스 시작
        analyzer.start_cli()
        
    except KeyboardInterrupt:
        logger.info("사용자가 프로그램을 중단했습니다")
        print("\n프로그램을 종료합니다.")
    except Exception as e:
        logger.error(f"예기치 않은 오류 발생: {str(e)}")
        print(f"오류 발생: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
