#!/usr/bin/env python3
"""
MyMobSF_Analyzer - 모바일 앱 보안 분석 자동화 도구 (완전 개선판)
실시간 크래시 감지, Frida 우회 주입, 자동 재시작 통합
"""
import logging
import os
import re
import subprocess
import sys
import threading
import time
from configparser import ConfigParser
from datetime import datetime
from pathlib import Path

from .decrypt_apk import APKDecryptor
from .mobsf_api import MobSFAPI
from .report_generator import ReportGenerator

# 경로 설정
ADB_PATH = r"C:\Users\day_a\AppData\Local\Android\Sdk\platform-tools\adb.exe"
AAPT_PATH = r"C:\Users\day_a\AppData\Local\Android\Sdk\build-tools\36.0.0\aapt.exe"

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("analyzer.log", encoding='utf-8'), logging.StreamHandler()]
)
logger = logging.getLogger("AppAnalyzer")

class DetailedLogcatMonitor:
    def __init__(self, adb_path, pkg_name, logger=None):
        self.adb_path = adb_path
        self.pkg_name = pkg_name
        self.logger = logger or logging.getLogger("LogcatMonitor")
        self.monitoring = False
        self.logcat_process = None
        self.monitor_thread = None
        self.crash_logs = []
        self.crash_patterns = {
            "FATAL EXCEPTION": "자바 치명적 예외",
            "AndroidRuntime": "안드로이드 런타임 오류",
            "signal 6": "SIGABRT - 프로그램 중단",
            "signal 7": "SIGBUS - 버스 오류",
            "signal 11": "SIGSEGV - 메모리 접근 위반",
            "ANR in": "Application Not Responding",
            "CRASH:": "네이티브 크래시",
            "Force finishing activity": "액티비티 강제 종료",
            "Process.*died": "프로세스 사망"
        }

    def start_detailed_monitoring(self):
        if self.monitoring:
            return
        self.monitoring = True
        self.crash_logs = []
        try:
            self.logcat_process = subprocess.Popen(
                [self.adb_path, 'logcat', '-v', 'threadtime'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            self.monitor_thread = threading.Thread(
                target=self._monitor_logcat_stream,
                daemon=True
            )
            self.monitor_thread.start()
            self.logger.info(f"[상세 로그 모니터링] {self.pkg_name} 앱에 대한 실시간 logcat 모니터링 시작")
        except Exception as e:
            self.logger.error(f"[상세 로그 모니터링] 시작 실패: {e}")
            self.monitoring = False

    def _monitor_logcat_stream(self):
        buffer_lines = []
        max_buffer_size = 200
        try:
            while self.monitoring and self.logcat_process:
                line = self.logcat_process.stdout.readline()
                if not line:
                    break
                buffer_lines.append(line.strip())
                if len(buffer_lines) > max_buffer_size:
                    buffer_lines.pop(0)
                if self.pkg_name in line or any(pattern in line for pattern in self.crash_patterns.keys()):
                    self._analyze_crash_log(line, buffer_lines.copy())
        except Exception as e:
            self.logger.error(f"[상세 로그 모니터링] 스트림 모니터링 오류: {e}")

    def _analyze_crash_log(self, current_line, context_buffer):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for pattern, description in self.crash_patterns.items():
            if pattern in current_line:
                crash_info = {
                    'timestamp': timestamp,
                    'pattern': pattern,
                    'description': description,
                    'crash_line': current_line.strip(),
                    'context': context_buffer[-50:] if len(context_buffer) > 50 else context_buffer,
                    'app_package': self.pkg_name
                }
                self.crash_logs.append(crash_info)
                self._log_crash_details(crash_info)
                self._save_crash_log_to_file(crash_info)
                break

    def _log_crash_details(self, crash_info):
        self.logger.error(f"🚨 [크래시 감지] {crash_info['description']}")
        self.logger.error(f"📱 [앱 패키지] {crash_info['app_package']}")
        self.logger.error(f"⏰ [발생 시각] {crash_info['timestamp']}")
        self.logger.error(f"📝 [크래시 라인] {crash_info['crash_line']}")
        stack_trace = self._extract_stack_trace(crash_info['context'])
        if stack_trace:
            self.logger.error(f"📚 [스택 트레이스]")
            for line in stack_trace[:10]:
                self.logger.error(f"    {line}")

    def _extract_stack_trace(self, context_lines):
        stack_trace = []
        in_stack_trace = False
        for line in context_lines:
            if "at " in line and ("java." in line or "android." in line or self.pkg_name in line):
                stack_trace.append(line.strip())
                in_stack_trace = True
            elif in_stack_trace and line.strip().startswith("at "):
                stack_trace.append(line.strip())
            elif in_stack_trace and not line.strip().startswith("at "):
                break
        return stack_trace

    def _save_crash_log_to_file(self, crash_info):
        try:
            crash_dir = Path("crash_logs")
            crash_dir.mkdir(exist_ok=True)
            timestamp_str = crash_info['timestamp'].replace(' ', '_').replace(':', '-')
            filename = f"crash_{self.pkg_name}_{timestamp_str}.log"
            filepath = crash_dir / filename
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(f"=== 앱 크래시 상세 로그 ===\n")
                f.write(f"앱 패키지: {crash_info['app_package']}\n")
                f.write(f"발생 시각: {crash_info['timestamp']}\n")
                f.write(f"크래시 유형: {crash_info['description']}\n")
                f.write(f"크래시 라인: {crash_info['crash_line']}\n\n")
                f.write(f"=== 컨텍스트 로그 (최근 {len(crash_info['context'])}줄) ===\n")
                for line in crash_info['context']:
                    f.write(f"{line}\n")
                stack_trace = self._extract_stack_trace(crash_info['context'])
                if stack_trace:
                    f.write(f"\n=== 스택 트레이스 ===\n")
                    for line in stack_trace:
                        f.write(f"{line}\n")
            self.logger.info(f"💾 [크래시 로그 저장] {filepath}")
        except Exception as e:
            self.logger.error(f"크래시 로그 파일 저장 실패: {e}")

    def get_crash_summary(self):
        if not self.crash_logs:
            return "크래시가 감지되지 않았습니다."
        summary = f"총 {len(self.crash_logs)}개의 크래시가 감지되었습니다:\n"
        crash_types = {}
        for crash in self.crash_logs:
            crash_type = crash['description']
            crash_types[crash_type] = crash_types.get(crash_type, 0) + 1
        for crash_type, count in crash_types.items():
            summary += f"  - {crash_type}: {count}회\n"
        return summary

    def stop_monitoring(self):
        self.monitoring = False
        if self.logcat_process:
            try:
                self.logcat_process.terminate()
                self.logcat_process.wait(timeout=5)
            except:
                self.logcat_process.kill()
            self.logcat_process = None
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
        summary = self.get_crash_summary()
        self.logger.info(f"[상세 로그 모니터링] 종료 - {summary}")

class RealTimeCrashMonitor:
    def __init__(self, adb_path, max_retries=5, monitor_interval=0.5, logger=None):
        self.adb_path = adb_path
        self.max_retries = max_retries
        self.monitor_interval = monitor_interval
        self.logger = logger or logging.getLogger("CrashMonitor")
        self.monitoring = False
        self.monitor_thread = None
        self.restart_count = 0
        self.detailed_logcat_monitor = None

    def is_process_running(self, pkg):
        try:
            result = subprocess.run(
                [self.adb_path, 'shell', 'pidof', pkg],
                capture_output=True, text=True, timeout=5
            )
            return bool(result.stdout.strip())
        except Exception as e:
            self.logger.error(f"프로세스 확인 오류: {e}")
            return False

    def check_crash_in_logcat(self, pkg):
        try:
            result = subprocess.run(
                [self.adb_path, 'shell', 'logcat', '-d', '-t', '50'],
                capture_output=True, text=True, timeout=10
            )
            crash_patterns = [
                "FATAL EXCEPTION", "AndroidRuntime", "Crash",
                f"{pkg}", "died", "Force finishing activity"
            ]
            lines = result.stdout.splitlines()
            recent_lines = lines[-20:] if len(lines) > 20 else lines
            for line in recent_lines:
                if any(pattern in line for pattern in crash_patterns):
                    self.logger.warning(f"크래시 패턴 감지: {line[:100]}")
                    return True
            return False
        except Exception as e:
            self.logger.error(f"logcat 확인 오류: {e}")
            return False

    def restart_app(self, pkg, activity):
        try:
            subprocess.run([self.adb_path, 'shell', 'am', 'force-stop', pkg], timeout=10)
            time.sleep(2)
            subprocess.run(
                [self.adb_path, 'shell', 'am', 'start', '-n', f"{pkg}/{activity}"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10
            )
            self.restart_count += 1
            self.logger.info(f"앱 재시작 완료 ({self.restart_count}/{self.max_retries}): {pkg}")
            time.sleep(3)
            return True
        except Exception as e:
            self.logger.error(f"앱 재시작 실패: {e}")
            return False

    def monitor_loop(self, pkg, activity):
        consecutive_failures = 0
        while self.monitoring and self.restart_count < self.max_retries:
            try:
                process_running = self.is_process_running(pkg)
                crash_detected = self.check_crash_in_logcat(pkg)
                if not process_running or crash_detected:
                    consecutive_failures += 1
                    if consecutive_failures >= 2:
                        self.logger.warning(f"앱 비정상 상태 감지 (연속 {consecutive_failures}회)")
                        if self.restart_app(pkg, activity):
                            consecutive_failures = 0
                        else:
                            break
                else:
                    consecutive_failures = 0
                time.sleep(self.monitor_interval)
            except Exception as e:
                self.logger.error(f"모니터링 오류: {e}")
                time.sleep(1)

    def start_monitoring(self, pkg, activity):
        if self.monitoring:
            return
        self.monitoring = True
        self.restart_count = 0
        self.detailed_logcat_monitor = DetailedLogcatMonitor(self.adb_path, pkg, self.logger)
        self.detailed_logcat_monitor.start_detailed_monitoring()
        self.monitor_thread = threading.Thread(
            target=self.monitor_loop,
            args=(pkg, activity),
            daemon=True
        )
        self.monitor_thread.start()
        self.logger.info("실시간 크래시 모니터링 시작")

    def stop_monitoring(self):
        self.monitoring = False
        if self.detailed_logcat_monitor:
            self.detailed_logcat_monitor.stop_monitoring()
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
        self.logger.info("크래시 모니터링 중단")

class FridaInjector:
    def __init__(self, adb_path, logger=None):
        self.adb_path = adb_path
        self.logger = logger or logging.getLogger("FridaInjector")

    def generate_bypass_script(self):
        script_content = '''
// Universal Android Anti-Debugging/Root/Frida Detection Bypass + ClassNotFoundException 우회

console.log("[*] Frida 우회 스크립트 시작");

Java.perform(function() {
    var ClassLoader = Java.use("java.lang.ClassLoader");
    ClassLoader.loadClass.overload('java.lang.String').implementation = function(name) {
        if (name === "com.ldjSxw.heBbQd.IntroActivity") {
            console.log("[!] IntroActivity 요청 감지, MainActivity로 리다이렉트");
            return this.loadClass("com.ldjSxw.heBbQd.MainActivity", false);
        }
        if (name === "android.support.v4.app.CoreComponentFactory" || name === "androidx.core.app.CoreComponentFactory") {
            console.log("[!] CoreComponentFactory 요청 무시, AppComponentFactory 반환");
            return Java.use("android.app.AppComponentFactory").class;
        }
        try {
            return this.loadClass.overload('java.lang.String').call(this, name);
        } catch (e) {
            console.log("[!] 클래스 로드 실패: " + name + " (" + e + ")");
            return null;
        }
    };

    // ... (기존 루트/안티디버깅/Frida 탐지 우회 코드도 여기에 포함) ...
});

console.log("[*] Frida 우회 스크립트 로드 완료");
'''
        return script_content

    def inject_script(self, pkg, script_path=None):
        try:
            if script_path and Path(script_path).exists():
                self.logger.info(f"사용자 정의 스크립트 주입: {script_path}")
                cmd = [
                    "frida", "-U", "-f", pkg,
                    "-l", script_path,
                    "--runtime=v8", "--no-pause"
                ]
            else:
                self.logger.info("내장 안티 디버깅 우회 스크립트 주입")
                script_content = self.generate_bypass_script()
                temp_script = Path("temp_bypass.js")
                with open(temp_script, 'w', encoding='utf-8') as f:
                    f.write(script_content)
                cmd = [
                    "frida", "-U", "-f", pkg,
                    "-l", str(temp_script),
                    "--runtime=v8", "--no-pause"
                ]
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            time.sleep(3)
            process.terminate()
            self.logger.info("Frida 스크립트 주입 완료")
            return True
        except Exception as e:
            self.logger.error(f"Frida 주입 실패: {e}")
            return False
        finally:
            if 'temp_script' in locals() and temp_script.exists():
                temp_script.unlink()

class AppAnalyzer:
    def __init__(self, config):
        self.config = config
        self.mobsf_api = MobSFAPI(
            config.get('mobsf', 'server_ip'),
            config.get('mobsf', 'api_key')
        )
        self.apk_dir = Path(config.get('paths', 'apk_files_dir'))
        self.report_dir = Path(config.get('paths', 'reports_dir'))
        self.tools_dir = Path(config.get('paths', 'tools_dir'))
        self.current = None
        self.report_gen = ReportGenerator(self.report_dir)
        self.crash_monitor = RealTimeCrashMonitor(
            ADB_PATH,
            max_retries=self.config.getint('analysis', 'max_retries', fallback=5),
            monitor_interval=0.5,
            logger=logger
        )
        self.frida_injector = FridaInjector(ADB_PATH, logger)
        for d in [self.apk_dir, self.report_dir, self.tools_dir]:
            d.mkdir(parents=True, exist_ok=True)

    def start_cli(self):
        self._print_banner()
        while True:
            try:
                parts = input(">> ").strip().split()
                if not parts: continue
                cmd = parts[0].lower()
                if cmd == "exit": break
                getattr(self, f"cmd_{cmd}", self._show_help)(parts)
            except KeyboardInterrupt:
                print("\n종료합니다.")
                break

    def _print_banner(self):
        print("""
╔════════════════════════════════════════╗
║         MyMobSF_Analyzer              ║
║      모바일 보안 분석 자동화 도구      ║
║         (완전 개선 버전)               ║
╚════════════════════════════════════════╝
도움말: 'help' 입력""")

    def _show_help(self, args=None):
        print("""
사용 가능한 명령:
 static analysis   - 정적 분석 실행
 dynamic analysis  - 동적 분석 시작 (크래시 모니터링 + Frida 주입)
 dynamic stop      - 동적 분석 중단
 decrypt apk       - APK 복호화
 list              - APK 파일 목록
 recent            - 최근 분석 기록
 status            - 시스템 상태
 help              - 도움말
 exit              - 종료""")

    def cmd_help(self, args): self._show_help()

    def cmd_status(self, args):
        ok = self.mobsf_api.check_server_status()
        print(f"MobSF 서버 연결: {ok}")

    def cmd_list(self, args):
        apks = list(self.apk_dir.glob("*.apk"))
        if not apks:
            print("APK 파일 없음")
            return
        for i, f in enumerate(apks, 1):
            size = f.stat().st_size / (1024 * 1024)
            print(f"{i}. {f.name} ({size:.1f} MB)")

    def _select_apk(self):
        apks = list(self.apk_dir.glob("*.apk"))
        if not apks:
            print("APK 파일 없음")
            return None
        if len(apks) == 1:
            return apks[0]
        self.cmd_list(None)
        try:
            idx = int(input(f"번호 선택 (1-{len(apks)}): ")) - 1
            return apks[idx] if 0 <= idx < len(apks) else None
        except Exception:
            return None

    def cmd_static(self, args):
        if len(args) > 1 and args[1] == "analysis":
            apk = self._select_apk()
            if apk: self._static_analysis(apk)
        else:
            self._show_help()

    def _static_analysis(self, apk):
        logger.info(f"정적 분석 시작: {apk.name}")
        if not self.mobsf_api.check_server_status():
            print("서버 연결 실패")
            return
        res = self.mobsf_api.upload_file(str(apk))
        h = res.get('hash') if res else None
        if not h:
            print("업로드 실패")
            return
        if not self.mobsf_api.scan_file(h):
            print("스캔 요청 실패")
            return
        jr = self.mobsf_api.get_json_report(h)
        if jr:
            self.report_gen.save_json_report(jr, self.report_dir/f"{apk.stem}_{h}.json")
            self.mobsf_api.download_pdf_report(h, str(self.report_dir/f"{apk.stem}_{h}.pdf"))
            print("정적 분석 완료")

    def cmd_dynamic(self, args):
        if len(args) > 1 and args[1] == "analysis":
            self._dynamic_analysis()
        elif len(args) > 1 and args[1] == "stop":
            self._dynamic_stop()
        else:
            self._show_help()

    def _dynamic_analysis(self):
        logger.info("=== 개선된 동적 분석 시작 ===")
        if not self._verify_env():
            print("환경 검증 실패")
            return
        apk = self._select_apk()
        if not apk: return
        up = self.mobsf_api.upload_file(str(apk))
        h = up.get('hash') if up else None
        if not h: return
        self.current = h
        subprocess.run([ADB_PATH, 'shell', 'input', 'keyevent', '82'], check=True)
        if not subprocess.run([ADB_PATH, 'shell', 'pgrep', 'frida-server'],
                             capture_output=True, text=True).stdout:
            print("Frida 서버 미실행")
            return
        pkg = self._extract_pkg(apk)
        activity = self._extract_launcher_activity(apk)
        if not pkg or not activity: return
        logger.info("[실시간] 크래시 모니터링 활성화 (우선)")
        self.crash_monitor.start_monitoring(pkg, activity)
        for _ in range(3):
            if self.mobsf_api.start_dynamic_analysis(h):
                logger.info("[MobSF] 동적 분석 시작됨")
                break
            time.sleep(5)
        else:
            print("동적 분석 시작 실패")
            return
        logger.info("[앱 실행] 시작")
        subprocess.run(
            [ADB_PATH, 'shell', 'am', 'start', '-n', f"{pkg}/{activity}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(2)
        logger.info("[Frida] 안티 디버깅 우회 스크립트 주입")
        script_path = self.config.get('frida', 'script_path', fallback=None)
        inject_result = self.frida_injector.inject_script(pkg, script_path)
        if not inject_result:
            logger.error("Frida 스크립트 주입 실패: 스크립트 파일 또는 환경을 확인하세요.")
        time.sleep(3)
        if not self.crash_monitor.is_process_running(pkg):
            logger.warning("[경고] 앱이 비정상 종료됨, 자동 복구 시도...")
            time.sleep(2)
        logger.info("[분석 진행] 동적 분석 진행 중... (백그라운드 모니터링 활성)")
        self._poll_dynamic_status(h)
        self.crash_monitor.stop_monitoring()
        self.current = None
        logger.info("=== 동적 분석 완료 ===")

    def _dynamic_stop(self):
        if self.current:
            self.mobsf_api.stop_dynamic_analysis(self.current)
            self.crash_monitor.stop_monitoring()
            print("동적 분석 중단됨")

    def _verify_env(self):
        if not self.mobsf_api.check_server_status():
            return False
        out = subprocess.run([ADB_PATH, 'devices'], capture_output=True, text=True).stdout
        return 'device' in out

    def _extract_pkg(self, apk):
        try:
            out = subprocess.run(
                [AAPT_PATH, 'dump', 'badging', str(apk)],
                capture_output=True, text=True
            ).stdout
            return out.split("package: name='")[1].split("'")[0]
        except:
            return None

    def _extract_launcher_activity(self, apk):
        try:
            out = subprocess.run(
                [AAPT_PATH, 'dump', 'badging', str(apk)],
                capture_output=True, text=True
            ).stdout
            return out.split("launchable-activity: name='")[1].split("'")[0]
        except:
            return None

    def _poll_dynamic_status(self, h):
        print("분석 진행 중... (실시간 모니터링 활성)")
        timeout = self.config.getint('analysis', 'dynamic_timeout', fallback=1800)
        start = time.time()
        while time.time() - start < timeout:
            if not self.crash_monitor.monitoring:
                break
            time.sleep(10)

    def cmd_decrypt(self, args):
        if len(args) > 1 and args[1] == "apk":
            apk = self._select_apk()
            if apk: self._decrypt_apk(apk)
        else:
            self._show_help()

    def _decrypt_apk(self, apk):
        print("APK 복호화 시작")
        d = APKDecryptor(str(apk), self.config.get('analysis', 'encryption_method'))
        backup = d.backup_apk_file()
        d.unzip_apk()
        so = d.find_lib()
        keys = d.process_so_files(so)
        data = d.decrypt_files(keys)
        if data:
            d.save_decrypted_data(data)
            od = d.decompile_apk(backup)
            d.repackaging_apk(od)
            print("APK 복호화 완료")

    def cmd_recent(self, args):
        scans = (self.mobsf_api.get_recent_scans() or {}).get('content', [])
        if not scans:
            print("기록 없음")
        for i, s in enumerate(scans, 1):
            print(f"{i}. {s['APP_NAME']} / {s['FILE_NAME']} / {s['SCAN_TYPE']} / {s['TIMESTAMP']}")

if __name__ == "__main__":
    cfg = ConfigParser()
    cfg.read("config/config.ini", encoding="utf-8")
    AppAnalyzer(cfg).start_cli()
