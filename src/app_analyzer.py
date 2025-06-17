#!/usr/bin/env python3
"""
MyMobSF_Analyzer - 모바일 앱 보안 분석 자동화 도구 (완전 개선판)
실시간 크래시 감지, Frida 우회 주입, 자동 재시작 통합
"""
import os
import sys
import time
import subprocess
import logging
import threading
from pathlib import Path
from configparser import ConfigParser

from .mobsf_api import MobSFAPI
from .decrypt_apk import APKDecryptor
from .report_generator import ReportGenerator

# 경로 설정
ADB_PATH = r"C:\Users\day_a\AppData\Local\Android\Sdk\platform-tools\adb.exe"
AAPT_PATH = r"C:\Users\day_a\AppData\Local\Android\Sdk\build-tools\36.0.0\aapt.exe"

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("analyzer.log"), logging.StreamHandler()]
)
logger = logging.getLogger("AppAnalyzer")

class RealTimeCrashMonitor:
    """실시간 크래시 모니터링 및 자동 복구 클래스"""
    def __init__(self, adb_path, max_retries=5, monitor_interval=0.5, logger=None):
        self.adb_path = adb_path
        self.max_retries = max_retries
        self.monitor_interval = monitor_interval
        self.logger = logger or logging.getLogger("CrashMonitor")
        self.monitoring = False
        self.monitor_thread = None
        self.restart_count = 0

    def is_process_running(self, pkg):
        """앱 프로세스 실행 여부 확인"""
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
        """logcat에서 실시간 크래시 패턴 감지"""
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
        """앱 강제 종료 후 재시작"""
        try:
            # 앱 강제 종료
            subprocess.run([self.adb_path, 'shell', 'am', 'force-stop', pkg], timeout=10)
            time.sleep(2)
            
            # 앱 재시작
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
        """실시간 모니터링 루프"""
        consecutive_failures = 0
        
        while self.monitoring and self.restart_count < self.max_retries:
            try:
                process_running = self.is_process_running(pkg)
                crash_detected = self.check_crash_in_logcat(pkg)
                
                if not process_running or crash_detected:
                    consecutive_failures += 1
                    if consecutive_failures >= 2:  # 연속 2회 실패 시 재시작
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
        """백그라운드 모니터링 시작"""
        if self.monitoring:
            return
            
        self.monitoring = True
        self.restart_count = 0
        self.monitor_thread = threading.Thread(
            target=self.monitor_loop, 
            args=(pkg, activity),
            daemon=True
        )
        self.monitor_thread.start()
        self.logger.info("실시간 크래시 모니터링 시작")

    def stop_monitoring(self):
        """모니터링 중단"""
        self.monitoring = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
        self.logger.info("크래시 모니터링 중단")

class FridaInjector:
    """Frida 스크립트 주입 관리 클래스"""
    def __init__(self, adb_path, logger=None):
        self.adb_path = adb_path
        self.logger = logger or logging.getLogger("FridaInjector")

    def generate_bypass_script(self):
        """안티 디버깅 우회 스크립트 생성"""
        script_content = '''
// Universal Android Anti-Debugging Bypass Script
console.log("[*] 안티 디버깅 우회 스크립트 시작");

Java.perform(function() {
    try {
        // 1. 루트 탐지 우회
        console.log("[+] 루트 탐지 우회 시작");
        
        var File = Java.use("java.io.File");
        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            if (path.indexOf("su") !== -1 || 
                path.indexOf("busybox") !== -1 || 
                path.indexOf("magisk") !== -1 ||
                path.indexOf("xposed") !== -1) {
                console.log("[+] 루트 파일 접근 차단: " + path);
                return false;
            }
            return this.exists();
        };

        // 2. 안티 디버깅 우회
        console.log("[+] 안티 디버깅 우회 시작");
        
        var Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function() {
            console.log("[+] 디버거 연결 상태 위조");
            return false;
        };

        // 3. ADB 감지 우회
        var Settings = Java.use("android.provider.Settings$Global");
        Settings.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function(resolver, name, def) {
            if (name === "adb_enabled") {
                console.log("[+] ADB 활성화 상태 위조");
                return 0;
            }
            return this.getInt(resolver, name, def);
        };

        // 4. Frida 탐지 우회
        console.log("[+] Frida 탐지 우회 시작");
        
        var System = Java.use("java.lang.System");
        System.getProperty.implementation = function(key) {
            if (key === "java.vm.name") {
                console.log("[+] VM 이름 위조");
                return "Dalvik";
            }
            return this.getProperty(key);
        };

        console.log("[*] 모든 우회 스크립트 적용 완료");
        
    } catch (e) {
        console.log("[-] 우회 스크립트 오류: " + e.toString());
    }
});

// Native 레벨 우회
Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
    onEnter: function(args) {
        var path = Memory.readUtf8String(args[0]);
        if (path.indexOf("su") !== -1 || 
            path.indexOf("magisk") !== -1 ||
            path.indexOf("frida") !== -1) {
            console.log("[+] Native 파일 접근 차단: " + path);
            args[0] = Memory.allocUtf8String("/dev/null");
        }
    }
});

console.log("[*] 안티 디버깅 우회 스크립트 로드 완료");
'''
        return script_content

    def inject_script(self, pkg, script_path=None):
        """Frida 스크립트 주입"""
        try:
            if script_path and Path(script_path).exists():
                # 파일에서 스크립트 로드
                self.logger.info(f"사용자 정의 스크립트 주입: {script_path}")
                cmd = [
                    "frida", "-U", "-f", pkg,
                    "-l", script_path,
                    "--runtime=v8", "--no-pause"
                ]
            else:
                # 내장 우회 스크립트 사용
                self.logger.info("내장 안티 디버깅 우회 스크립트 주입")
                script_content = self.generate_bypass_script()
                
                # 임시 스크립트 파일 생성
                temp_script = Path("temp_bypass.js")
                with open(temp_script, 'w', encoding='utf-8') as f:
                    f.write(script_content)
                
                cmd = [
                    "frida", "-U", "-f", pkg,
                    "-l", str(temp_script),
                    "--runtime=v8", "--no-pause"
                ]

            # 비동기 주입 실행
            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            
            # 3초 후 프로세스 종료 (주입 완료)
            time.sleep(3)
            process.terminate()
            
            self.logger.info("Frida 스크립트 주입 완료")
            return True
            
        except Exception as e:
            self.logger.error(f"Frida 주입 실패: {e}")
            return False
        finally:
            # 임시 파일 정리
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
        
        # 모니터링 및 주입 컴포넌트 초기화
        self.crash_monitor = RealTimeCrashMonitor(
            ADB_PATH,
            max_retries=self.config.getint('analysis', 'max_retries', fallback=5),
            monitor_interval=0.5,
            logger=logger
        )
        self.frida_injector = FridaInjector(ADB_PATH, logger)
        
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
        
        # 환경 검증
        if not self._verify_env():
            print("환경 검증 실패")
            return
            
        # APK 선택 및 업로드
        apk = self._select_apk()
        if not apk: return
        
        up = self.mobsf_api.upload_file(str(apk))
        h = up.get('hash') if up else None
        if not h: return
        self.current = h

        # 잠금화면 해제
        subprocess.run([ADB_PATH, 'shell', 'input', 'keyevent', '82'], check=True)

        # Frida 서버 확인
        if not subprocess.run([ADB_PATH, 'shell', 'pgrep', 'frida-server'], 
                             capture_output=True, text=True).stdout:
            print("Frida 서버 미실행")
            return

        # 패키지 정보 추출
        pkg = self._extract_pkg(apk)
        activity = self._extract_launcher_activity(apk)
        if not pkg or not activity: return

        # ★ 핵심 개선: 즉시 크래시 모니터링 시작
        logger.info("🔄 실시간 크래시 모니터링 활성화 (우선)")
        self.crash_monitor.start_monitoring(pkg, activity)

        # MobSF 동적 분석 시작
        for _ in range(3):
            if self.mobsf_api.start_dynamic_analysis(h):
                logger.info("📱 MobSF 동적 분석 시작됨")
                break
            time.sleep(5)
        else:
            print("동적 분석 시작 실패")
            return

        # 앱 실행
        logger.info("🚀 앱 실행 시작")
        subprocess.run(
            [ADB_PATH, 'shell', 'am', 'start', '-n', f"{pkg}/{activity}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(2)

        # ★ Frida 우회 스크립트 즉시 주입
        logger.info("💉 Frida 안티 디버깅 우회 스크립트 주입")
        script_path = self.config.get('frida', 'script_path', fallback=None)
        self.frida_injector.inject_script(pkg, script_path)

        # 앱 상태 검증
        time.sleep(3)
        if not self.crash_monitor.is_process_running(pkg):
            logger.warning("⚠️ 앱이 비정상 종료됨, 자동 복구 시도...")
            time.sleep(2)

        # 동적 분석 진행
        logger.info("📊 동적 분석 진행 중... (백그라운드 모니터링 활성)")
        self._poll_dynamic_status(h)
        
        # 정리
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
