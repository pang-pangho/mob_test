#!/usr/bin/env python3

"""
MyMobSF_Analyzer - 모바일 앱 보안 분석 자동화 도구 (크래시 감지 및 자동 재시작 통합)
"""

import os
import sys
import time
import subprocess
import logging
from pathlib import Path

from .mobsf_api import MobSFAPI
from .decrypt_apk import APKDecryptor
from .report_generator import ReportGenerator
from .crash_monitor import CrashMonitor  # 새로 추가

# 1. ADB 및 AAPT 절대 경로 설정
ADB_PATH = r"C:\Users\day_a\AppData\Local\Android\Sdk\platform-tools\adb.exe"
AAPT_PATH = r"C:\Users\day_a\AppData\Local\Android\Sdk\build-tools\36.0.0\aapt.exe"

# 2. 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("analyzer.log"), logging.StreamHandler()]
)
logger = logging.getLogger("AppAnalyzer")

class AppAnalyzer:
    def __init__(self, config):
        self.config = config
        self.mobsf_api = MobSFAPI(
            config.get('mobsf','server_ip'),
            config.get('mobsf','api_key')
        )
        self.apk_dir = Path(config.get('paths','apk_files_dir'))
        self.report_dir = Path(config.get('paths','reports_dir'))
        self.tools_dir = Path(config.get('paths','tools_dir'))
        self.current = None
        self.report_gen = ReportGenerator(self.report_dir)
        # CrashMonitor 인스턴스 생성
        self.crash_monitor = CrashMonitor(
            ADB_PATH,
            max_retries=self.config.getint('analysis','max_retries',fallback=5),
            restart_delay=self.config.getint('analysis','restart_delay',fallback=3),
            logger=logger
        )
        # 디렉토리 자동 생성
        for d in [self.apk_dir, self.report_dir, self.tools_dir]:
            d.mkdir(parents=True, exist_ok=True)

    def start_cli(self):
        self._print_banner()
        while True:
            try:
                parts = input(">> ").strip().split()
                if not parts: continue
                cmd = parts[0].lower()
                if cmd == "exit":
                    break
                getattr(self, f"cmd_{cmd}", self._show_help)(parts)
            except KeyboardInterrupt:
                print("\n종료합니다.")
                break

    def _print_banner(self):
        print("""
╔════════════════════════════════════════╗
║         MyMobSF_Analyzer              ║
║      모바일 보안 분석 자동화 도구      ║
╚════════════════════════════════════════╝
도움말: 'help' 입력
""")

    def _show_help(self, args=None):
        print("""
사용 가능한 명령:
 static analysis   - 정적 분석 실행
 dynamic analysis  - 동적 분석 시작
 dynamic stop      - 동적 분석 중단
 decrypt apk       - APK 복호화
 list              - APK 파일 목록
 recent            - 최근 분석 기록
 status            - 시스템 상태
 help              - 도움말
 exit              - 종료
""")

    def cmd_help(self, args): self._show_help()

    def cmd_status(self, args):
        ok = self.mobsf_api.check_server_status()
        print(f"MobSF 서버 연결: {ok}")

    def cmd_list(self, args):
        apks = list(self.apk_dir.glob("*.apk"))
        if not apks:
            print("APK 파일 없음")
            return
        for i,f in enumerate(apks,1):
            size = f.stat().st_size/(1024*1024)
            print(f"{i}. {f.name} ({size:.1f} MB)")

    def _select_apk(self):
        apks = list(self.apk_dir.glob("*.apk"))
        if not apks:
            print("APK 파일 없음"); return None
        if len(apks)==1:
            return apks[0]
        self.cmd_list(None)
        try:
            idx = int(input(f"번호 선택 (1-{len(apks)}): ")) - 1
            return apks[idx] if 0<=idx<len(apks) else None
        except Exception:
            return None

    def cmd_static(self, args):
        if len(args)>1 and args[1]=="analysis":
            apk=self._select_apk()
            if apk: self._static_analysis(apk)
        else:
            self._show_help()

    def _static_analysis(self, apk):
        logger.info(f"정적 분석 시작: {apk.name}")
        if not self.mobsf_api.check_server_status():
            print("서버 연결 실패"); return
        res = self.mobsf_api.upload_file(str(apk))
        h = res.get('hash') if res else None
        if not h:
            print("업로드 실패"); return
        if not self.mobsf_api.scan_file(h):
            print("스캔 요청 실패"); return
        jr = self.mobsf_api.get_json_report(h)
        if jr:
            self.report_gen.save_json_report(jr, self.report_dir/f"{apk.stem}_{h}.json")
            self.mobsf_api.download_pdf_report(h, str(self.report_dir/f"{apk.stem}_{h}.pdf"))
            print("정적 분석 완료")

    def cmd_dynamic(self, args):
        if len(args)>1 and args[1]=="analysis":
            self._dynamic_analysis()
        elif len(args)>1 and args[1]=="stop":
            self._dynamic_stop()
        else:
            self._show_help()

    def _dynamic_analysis(self):
        logger.info("동적 분석 시작")
        if not self._verify_env():
            print("환경 검증 실패"); return
        apk = self._select_apk()
        if not apk: return
        up = self.mobsf_api.upload_file(str(apk))
        h = up.get('hash') if up else None
        if not h:
            print("업로드 실패"); return
        self.current = h

        # 잠금화면 해제
        subprocess.run([ADB_PATH,'shell','input','keyevent','82'], check=True)

        # Frida 서버 확인
        if not subprocess.run([ADB_PATH,'shell','pgrep','frida-server'],
                             capture_output=True,text=True).stdout:
            print("Frida 서버 미실행"); return

        # 동적 분석 시작 재시도
        for _ in range(3):
            if self.mobsf_api.start_dynamic_analysis(h):
                logger.info("동적 분석 시작됨")
                break
            time.sleep(5)
        else:
            print("동적 분석 시작 실패"); return

        # 패키지명 및 런처 액티비티 추출
        pkg = self._extract_pkg(apk)
        activity = self._extract_launcher_activity(apk)
        if not pkg or not activity:
            print("패키지명 또는 런처 액티비티 추출 실패"); return

        # 런처 액티비티 직접 실행
        subprocess.run([ADB_PATH,'shell','am','start','-n',f"{pkg}/{activity}"],
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        time.sleep(8) # 충분한 대기 시간

        # 크래시 감지 및 자동 재시작 통합
        if self.config.getboolean('analysis','crash_detection',fallback=True) and \
           self.config.getboolean('analysis','auto_restart',fallback=True):
            logger.info("크래시 모니터링 및 자동 재시작 활성화")
            ok = self.crash_monitor.monitor_and_restart(pkg, activity)
            if not ok:
                print("앱 실행 실패 (자동 재시작 시도 후에도 실패)")
                return
        else:
            # 포커스 확인만 수행
            focus = subprocess.run([ADB_PATH,'shell',
                'dumpsys window windows | findstr mCurrentFocus'],
                shell=True,capture_output=True,text=True).stdout
            if pkg not in focus:
                print("앱 실행 실패"); return

        # 상태 폴링 및 리포트 다운로드
        self._poll_dynamic_status(h)
        self.current=None

    def _dynamic_stop(self):
        if self.current:
            self.mobsf_api.stop_dynamic_analysis(self.current)
            print("동적 분석 중단됨")

    def _verify_env(self):
        if not self.mobsf_api.check_server_status():
            return False
        out = subprocess.run([ADB_PATH,'devices'],capture_output=True,text=True).stdout
        return 'device' in out

    def _extract_pkg(self, apk):
        try:
            out = subprocess.run([AAPT_PATH,'dump','badging',str(apk)],
                                 capture_output=True,text=True).stdout
            return out.split("package: name='")[1].split("'")[0]
        except:
            return None

    def _extract_launcher_activity(self, apk):
        try:
            out = subprocess.run([AAPT_PATH,'dump','badging',str(apk)],
                                 capture_output=True,text=True).stdout
            return out.split("launchable-activity: name='")[1].split("'")[0]
        except:
            return None

    def _poll_dynamic_status(self, h):
        print("분석 진행 중...")
        timeout = self.config.getint('analysis','dynamic_timeout',fallback=1800)
        start = time.time()
        last=None
        while time.time()-start < timeout:
            # MobSF 동적 분석 상태 체크
            time.sleep(10)
            # 상태 확인 및 리포트 다운로드 등

    def cmd_decrypt(self, args):
        if len(args)>1 and args[1]=="apk":
            apk=self._select_apk();
            if apk: self._decrypt_apk(apk)
        else:
            self._show_help()

    def _decrypt_apk(self, apk):
        print("APK 복호화 시작")
        d = APKDecryptor(str(apk),self.config.get('analysis','encryption_method'))
        backup = d.backup_apk_file(); d.unzip_apk()
        so = d.find_lib(); keys = d.process_so_files(so)
        data = d.decrypt_files(keys)
        if data:
            d.save_decrypted_data(data); od=d.decompile_apk(backup); d.repackaging_apk(od)
            print("APK 복호화 완료")

    def cmd_recent(self, args):
        scans=(self.mobsf_api.get_recent_scans() or {}).get('content',[])
        if not scans:
            print("기록 없음")
        for i,s in enumerate(scans,1):
            print(f"{i}. {s['APP_NAME']} / {s['FILE_NAME']} / {s['SCAN_TYPE']} / {s['TIMESTAMP']}")

if __name__=="__main__":
    import configparser
    cfg = configparser.ConfigParser()
    cfg.read("config/config.ini",encoding="utf-8")
    AppAnalyzer(cfg).start_cli()
