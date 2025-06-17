"""
APK 암호화 해제 클래스
암호화된 APK 파일의 복호화 및 재패키징 기능
"""

import os
import shutil
import zipfile
import subprocess
import fnmatch
import time
from pathlib import Path
from Crypto.Cipher import AES, DES, Blowfish
from Crypto.Util.Padding import unpad
from elftools.elf.elffile import ELFFile
import logging

class APKDecryptor:
    """APK 암호화 해제 클래스"""
    
    def __init__(self, apk_path, encryption_method=None):
        """
        APK 복호화기 초기화
        
        Args:
            apk_path (str): APK 파일 경로
            encryption_method (str): 암호화 방식 (기본값: AES-256-ECB)
        """
        self.original_apk = apk_path
        self.encryption_method = encryption_method or "AES-256-ECB"
        self.logger = logging.getLogger(__name__)
        
        # 작업 디렉토리 설정
        self.work_dir = Path(apk_path).parent / "decrypt_work"
        self.decrypt_extract_to_path = self.work_dir / "extracted"
        self.output_directory_path = self.work_dir / "output"
        
        # 디렉토리 생성
        self.work_dir.mkdir(exist_ok=True)
        self.decrypt_extract_to_path.mkdir(exist_ok=True)
        self.output_directory_path.mkdir(exist_ok=True)
        
        self.encrypted_dex = []
    
    def backup_apk_file(self):
        """APK 파일 백업"""
        try:
            backup_name = f"{Path(self.original_apk).stem}_backup.apk"
            backup_path = self.work_dir / backup_name
            shutil.copy2(self.original_apk, backup_path)
            self.logger.info(f"APK 백업 완료: {backup_path}")
            return str(backup_path)
        except Exception as e:
            self.logger.error(f"APK 백업 실패: {str(e)}")
            return None
    
    def unzip_apk(self):
        """APK 파일 압축 해제"""
        try:
            with zipfile.ZipFile(self.original_apk, 'r') as zip_ref:
                zip_ref.extractall(self.decrypt_extract_to_path)
            self.logger.info(f"APK 압축 해제 완료: {self.decrypt_extract_to_path}")
            return True
        except Exception as e:
            self.logger.error(f"APK 압축 해제 실패: {str(e)}")
            return False
    
    def classify_dex_files(self):
        """DEX 파일 분류 (암호화된 파일과 일반 파일)"""
        true_dex_files = []
        encrypt_dex_files = []
        
        try:
            # DEX 파일 검색
            files_found = []
            for root, dirs, files in os.walk(self.decrypt_extract_to_path):
                for file in files:
                    if file.endswith('.dex'):
                        files_found.append(os.path.join(root, file))
            
            if not files_found:
                self.logger.warning("DEX 파일을 찾을 수 없습니다.")
                return true_dex_files, encrypt_dex_files
            
            # DEX 파일 분류
            for file_path in files_found:
                try:
                    with open(file_path, 'rb') as file:
                        magic = file.read(4)
                    
                    magic_string = magic.decode(errors='ignore')
                    if magic_string == 'dex\n':
                        true_dex_files.append(file_path)
                    else:
                        encrypt_dex_files.append(file_path)
                        
                except Exception as e:
                    self.logger.error(f"파일 읽기 오류 {file_path}: {str(e)}")
                    continue
            
            self.logger.info(f"일반 DEX 파일: {len(true_dex_files)}개")
            self.logger.info(f"암호화된 DEX 파일: {len(encrypt_dex_files)}개")
            
        except Exception as e:
            self.logger.error(f"DEX 파일 분류 중 오류: {str(e)}")
        
        return true_dex_files, encrypt_dex_files
    
    def find_lib(self):
        """SO 라이브러리 파일 검색"""
        so_files = []
        try:
            for root, dirs, files in os.walk(self.decrypt_extract_to_path):
                for file in files:
                    if file.endswith('.so'):
                        so_files.append(os.path.join(root, file))
            
            self.logger.info(f"SO 파일 {len(so_files)}개 발견")
            
        except Exception as e:
            self.logger.error(f"SO 파일 검색 중 오류: {str(e)}")
        
        return so_files
    
    def process_so_files(self, so_files_paths):
        """SO 파일에서 암호화 키 추출"""
        all_keys = []
        
        for so_file_path in so_files_paths:
            try:
                with open(so_file_path, 'rb') as f:
                    elffile = ELFFile(f)
                    keys = self.extract_keys_from_elf(elffile)
                    all_keys.extend(keys)
                    
            except Exception as e:
                self.logger.error(f"SO 파일 처리 중 오류 {so_file_path}: {str(e)}")
                continue
        
        # 중복 제거
        unique_keys = list(set(all_keys))
        self.logger.info(f"추출된 키 {len(unique_keys)}개")
        
        return unique_keys
    
    def extract_keys_from_elf(self, elffile):
        """ELF 파일에서 암호화 키 추출"""
        specific_lengths = {16, 24, 32}  # AES 키 길이
        found_strings = []
        
        try:
            for section in elffile.iter_sections():
                if section.data():
                    strings = self.find_strings_of_specific_lengths(
                        section.data(), specific_lengths
                    )
                    found_strings.extend(strings)
        except Exception as e:
            self.logger.error(f"ELF 파일에서 키 추출 중 오류: {str(e)}")
        
        return found_strings
    
    def find_strings_of_specific_lengths(self, data, lengths):
        """특정 길이의 문자열 추출"""
        strings = []
        result = ""
        
        for c in data:
            if 32 <= c < 127:  # 출력 가능한 ASCII 문자
                result += chr(c)
            else:
                if len(result) in lengths:
                    strings.append(result)
                result = ""
        
        if len(result) in lengths:
            strings.append(result)
        
        return strings
    
    def decrypt_files(self, keys_str):
        """파일 암호화 해제"""
        if not keys_str:
            self.logger.error("암호화 키가 없습니다.")
            return None
        
        keys = [key.encode() for key in keys_str]
        
        try:
            true_dex, self.encrypted_dex = self.classify_dex_files()
            
            if not self.encrypted_dex:
                self.logger.info("암호화된 파일이 없습니다.")
                return None
            
            for encrypted_dex_path in self.encrypted_dex:
                for key in keys:
                    # 다양한 암호화 방식 시도
                    for method in ['AES', 'DES', 'Blowfish']:
                        for key_length in [128, 192, 256]:
                            for mode in ['ECB']:
                                try:
                                    encryption_spec = f"{method}-{key_length}-{mode}"
                                    decrypted_data = self.decrypt_file(
                                        encrypted_dex_path, key, encryption_spec
                                    )
                                    
                                    if decrypted_data and decrypted_data[:3] == b'dex':
                                        self.logger.info(f"복호화 성공: {encrypted_dex_path}")
                                        return decrypted_data
                                        
                                except Exception:
                                    continue
            
            self.logger.error("복호화 실패: 올바른 키를 찾을 수 없습니다.")
            return None
            
        except Exception as e:
            self.logger.error(f"파일 복호화 중 오류: {str(e)}")
            return None
    
    def decrypt_file(self, file_path, key, encryption_spec):
        """단일 파일 복호화"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"파일을 찾을 수 없습니다: {file_path}")
        
        method, key_length_str, mode = encryption_spec.split('-')
        key_length = int(key_length_str) // 8
        
        # 키 길이 조정
        if len(key) < key_length:
            key = key.ljust(key_length, b'\x00')
        elif len(key) > key_length:
            key = key[:key_length]
        
        # 암호화 방식에 따른 복호화
        cipher = None
        if method == 'AES':
            cipher = AES.new(key, AES.MODE_ECB)
        elif method == 'DES' and len(key) == 8:
            cipher = DES.new(key, DES.MODE_ECB)
        elif method == 'Blowfish' and (4 <= len(key) <= 56):
            cipher = Blowfish.new(key, Blowfish.MODE_ECB)
        else:
            raise ValueError(f"지원하지 않는 암호화 방식: {method}")
        
        # 파일 읽기 및 복호화
        with open(file_path, 'rb') as encrypted_file:
            ciphertext = encrypted_file.read()
        
        decrypted_data = cipher.decrypt(ciphertext)
        
        try:
            decrypted_data = unpad(decrypted_data, cipher.block_size)
        except ValueError:
            # 패딩이 없는 경우 그대로 사용
            pass
        
        return decrypted_data
    
    def save_decrypted_data(self, decrypted_data):
        """복호화된 데이터 저장"""
        try:
            # 기존 DEX 파일 개수 확인
            dex_count = len(list(self.decrypt_extract_to_path.glob("*.dex")))
            
            if dex_count == 0:
                filename = "classes.dex"
            else:
                filename = f"classes{dex_count}.dex"
            
            output_path = self.decrypt_extract_to_path / filename
            
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            self.logger.info(f"복호화된 파일 저장: {output_path}")
            return str(output_path)
            
        except Exception as e:
            self.logger.error(f"복호화된 데이터 저장 실패: {str(e)}")
            return None
    
    def decompile_apk(self, apk_path):
        """APK 디컴파일"""
        try:
            apktool_path = Path("tools/apktool.bat")
            if not apktool_path.exists():
                apktool_path = Path("tools/apktool.jar")
                if not apktool_path.exists():
                    raise FileNotFoundError("apktool을 찾을 수 없습니다.")
            
            output_dir = self.output_directory_path / "decompiled"
            output_dir.mkdir(exist_ok=True)
            
            if apktool_path.suffix == '.bat':
                command = [str(apktool_path), "d", apk_path, "-o", str(output_dir)]
            else:
                command = ["java", "-jar", str(apktool_path), "d", apk_path, "-o", str(output_dir)]
            
            result = subprocess.run(
                command, 
                capture_output=True, 
                text=True, 
                timeout=300
            )
            
            if result.returncode == 0:
                self.logger.info(f"APK 디컴파일 완료: {output_dir}")
                return str(output_dir)
            else:
                self.logger.error(f"APK 디컴파일 실패: {result.stderr}")
                return None
                
        except Exception as e:
            self.logger.error(f"APK 디컴파일 중 오류: {str(e)}")
            return None
    
    def repackaging_apk(self, decompiled_dir):
        """APK 재패키징"""
        try:
            apktool_path = Path("tools/apktool.bat")
            if not apktool_path.exists():
                apktool_path = Path("tools/apktool.jar")
                if not apktool_path.exists():
                    raise FileNotFoundError("apktool을 찾을 수 없습니다.")
            
            output_apk = self.output_directory_path / f"{Path(self.original_apk).stem}_decrypted.apk"
            
            if apktool_path.suffix == '.bat':
                command = [str(apktool_path), "b", decompiled_dir, "-o", str(output_apk)]
            else:
                command = ["java", "-jar", str(apktool_path), "b", decompiled_dir, "-o", str(output_apk)]
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                self.logger.info(f"APK 재패키징 완료: {output_apk}")
                
                # APK 서명
                signed_apk = self.sign_apk(str(output_apk))
                return signed_apk if signed_apk else str(output_apk)
            else:
                self.logger.error(f"APK 재패키징 실패: {result.stderr}")
                return None
                
        except Exception as e:
            self.logger.error(f"APK 재패키징 중 오류: {str(e)}")
            return None
    
    def sign_apk(self, apk_path):
        """APK 파일 서명"""
        try:
            keystore_name = f"{Path(self.original_apk).stem}_keystore.jks"
            keystore_path = self.output_directory_path / keystore_name
            alias = Path(self.original_apk).stem
            
            # 키스토어 생성
            keytool_cmd = [
                "keytool", "-genkey", "-v",
                "-keystore", str(keystore_path),
                "-alias", alias,
                "-keyalg", "RSA",
                "-keysize", "2048",
                "-validity", "365"
            ]
            
            # 키스토어 생성 (자동 입력)
            process = subprocess.Popen(
                keytool_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # 자동으로 키스토어 정보 입력
            inputs = "123456\n" * 2 + "MyOrg\n" * 6 + "yes\n"
            stdout, stderr = process.communicate(input=inputs)
            
            if process.returncode == 0:
                self.logger.info("키스토어 생성 완료")
                
                # APK 서명
                signed_apk = apk_path.replace('.apk', '_signed.apk')
                jarsigner_cmd = [
                    "jarsigner",
                    "-verbose",
                    "-sigalg", "SHA1withRSA",
                    "-digestalg", "SHA1",
                    "-keystore", str(keystore_path),
                    "-storepass", "123456",
                    apk_path,
                    alias
                ]
                
                result = subprocess.run(
                    jarsigner_cmd,
                    capture_output=True,
                    text=True
                )
                
                if result.returncode == 0:
                    shutil.copy2(apk_path, signed_apk)
                    self.logger.info(f"APK 서명 완료: {signed_apk}")
                    return signed_apk
                else:
                    self.logger.error(f"APK 서명 실패: {result.stderr}")
                    return None
            else:
                self.logger.error(f"키스토어 생성 실패: {stderr}")
                return None
                
        except Exception as e:
            self.logger.error(f"APK 서명 중 오류: {str(e)}")
            return None
