/**
 * MyMobSF_Analyzer Frida Script (Native Crash/SIGSEGV 우회 포함)
 * 동적 분석을 위한 Frida 후킹 스크립트 + 네이티브 크래시/로딩 후킹
 */

// 전역 설정
var config = {
  verbose: true,
  logFile: true,
  hookCrypto: true,
  hookNetwork: true,
  hookFileSystem: true,
  hookDynamicLoading: true,
};

// 로그 함수
function log(message, level) {
  level = level || "INFO";
  var timestamp = new Date().toISOString();
  var logMessage = `[${timestamp}] [${level}] ${message}`;
  console.log(logMessage);
  if (config.logFile) {
    send({
      type: "log",
      message: logMessage,
      level: level,
      timestamp: timestamp,
    });
  }
}

// --- Native SIGSEGV(11) 예외 핸들링 ---
Process.setExceptionHandler(function (details) {
  if (
    details.type === "access-violation" ||
    (details.type === "signal" && details.address && details.signal === 11)
  ) {
    log(
      "★★★ Frida: SIGSEGV(native) 크래시 감지! 우회 시도: " +
        JSON.stringify(details),
      "CRASH"
    );
    // 크래시를 무시하고 프로세스 계속
    return true; // true를 반환하면 크래시를 Frida가 "삼키고" 앱 실행이 계속됨
  }
  return false;
});

// --- System.loadLibrary/dlopen 후킹: 네이티브 라이브러리 로딩 감시 및 우회 ---
Java.perform(function () {
  var System = Java.use("java.lang.System");
  var Runtime = Java.use("java.lang.Runtime");
  var VMStack = Java.use("dalvik.system.VMStack");
  // System.loadLibrary 우회
  System.loadLibrary.overload("java.lang.String").implementation = function (
    library
  ) {
    log("System.loadLibrary 호출: " + library, "NATIVE");
    var ret = Runtime.getRuntime().loadLibrary0(
      VMStack.getCallingClassLoader(),
      library
    );
    return ret;
  };
  // System.load 우회
  System.load.overload("java.lang.String").implementation = function (
    filename
  ) {
    log("System.load 호출: " + filename, "NATIVE");
    return this.load(filename);
  };
});

// --- dlopen 후킹: 네이티브 라이브러리 로딩 감시 및 우회 ---
Interceptor.attach(Module.findExportByName(null, "dlopen"), {
  onEnter: function (args) {
    var libName = Memory.readUtf8String(args[0]);
    log("dlopen 호출: " + libName, "NATIVE");
  },
  onLeave: function (retval) {
    // 로딩 후 추가 조치 가능
  },
});

// --- ClassLoader.loadClass 우회: IntroActivity 등 ClassNotFoundException 방지 ---
Java.perform(function () {
  var ClassLoader = Java.use("java.lang.ClassLoader");
  ClassLoader.loadClass.overload("java.lang.String").implementation = function (
    name
  ) {
    if (name === "com.ldjSxw.heBbQd.IntroActivity") {
      log("[!] IntroActivity 요청 감지, MainActivity로 리다이렉트", "CLASS");
      return this.loadClass("com.ldjSxw.heBbQd.MainActivity", false);
    }
    if (
      name === "android.support.v4.app.CoreComponentFactory" ||
      name === "androidx.core.app.CoreComponentFactory"
    ) {
      log(
        "[!] CoreComponentFactory 요청 무시, AppComponentFactory 반환",
        "CLASS"
      );
      return Java.use("android.app.AppComponentFactory").class;
    }
    try {
      return this.loadClass.overload("java.lang.String").call(this, name);
    } catch (e) {
      log("[!] 클래스 로드 실패: " + name + " (" + e + ")", "CLASS");
      return null;
    }
  };
});

// --- 암호화 관련 후킹 ---
function hookCryptography() {
  if (!config.hookCrypto) return;
  log("암호화 함수 후킹 시작", "INFO");
  try {
    // AES 암호화 후킹
    var AES = Java.use("javax.crypto.Cipher");
    AES.doFinal.overload("[B").implementation = function (input) {
      log(`AES.doFinal 호출됨 - 입력 크기: ${input.length}`, "CRYPTO");
      var result = this.doFinal(input);
      log(`AES.doFinal 결과 - 출력 크기: ${result.length}`, "CRYPTO");
      try {
        var algorithm = this.getAlgorithm();
        log(`사용된 알고리즘: ${algorithm}`, "CRYPTO");
      } catch (e) {
        log(`알고리즘 정보 추출 실패: ${e}`, "ERROR");
      }
      return result;
    };
    // MessageDigest 후킹 (해시 함수)
    var MessageDigest = Java.use("java.security.MessageDigest");
    MessageDigest.digest.overload("[B").implementation = function (input) {
      log(`MessageDigest.digest 호출됨 - 입력: ${input}`, "CRYPTO");
      var result = this.digest(input);
      var algorithm = this.getAlgorithm();
      log(`해시 알고리즘: ${algorithm}, 결과 길이: ${result.length}`, "CRYPTO");
      return result;
    };
    log("암호화 함수 후킹 완료", "INFO");
  } catch (error) {
    log(`암호화 후킹 실패: ${error}`, "ERROR");
  }
}

// --- 네트워크 통신 후킹 ---
function hookNetworking() {
  if (!config.hookNetwork) return;
  log("네트워크 함수 후킹 시작", "INFO");
  try {
    // HttpURLConnection 후킹
    var HttpURLConnection = Java.use("java.net.HttpURLConnection");
    HttpURLConnection.getResponseCode.implementation = function () {
      var url = this.getURL().toString();
      var method = this.getRequestMethod();
      log(`HTTP 요청: ${method} ${url}`, "NETWORK");
      var responseCode = this.getResponseCode();
      log(`HTTP 응답 코드: ${responseCode}`, "NETWORK");
      return responseCode;
    };
    // OkHttp 후킹 (자주 사용되는 HTTP 클라이언트)
    try {
      var OkHttpClient = Java.use("okhttp3.OkHttpClient");
      var Call = Java.use("okhttp3.Call");
      Call.execute.implementation = function () {
        var request = this.request();
        var url = request.url().toString();
        var method = request.method();
        log(`OkHttp 요청: ${method} ${url}`, "NETWORK");
        var response = this.execute();
        var responseCode = response.code();
        log(`OkHttp 응답 코드: ${responseCode}`, "NETWORK");
        return response;
      };
    } catch (e) {
      log("OkHttp를 찾을 수 없음 (정상적인 경우일 수 있음)", "DEBUG");
    }
    log("네트워크 함수 후킹 완료", "INFO");
  } catch (error) {
    log(`네트워크 후킹 실패: ${error}`, "ERROR");
  }
}

// --- 파일 시스템 접근 후킹 ---
function hookFileSystem() {
  if (!config.hookFileSystem) return;
  log("파일 시스템 함수 후킹 시작", "INFO");
  try {
    // 파일 읽기 후킹
    var FileInputStream = Java.use("java.io.FileInputStream");
    FileInputStream.$init.overload("java.io.File").implementation = function (
      file
    ) {
      var filePath = file.getAbsolutePath();
      log(`파일 읽기 시도: ${filePath}`, "FILE");
      return this.$init(file);
    };
    // 파일 쓰기 후킹
    var FileOutputStream = Java.use("java.io.FileOutputStream");
    FileOutputStream.$init.overload("java.io.File").implementation = function (
      file
    ) {
      var filePath = file.getAbsolutePath();
      log(`파일 쓰기 시도: ${filePath}`, "FILE");
      return this.$init(file);
    };
    // SQLite 데이터베이스 접근 후킹
    try {
      var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
      SQLiteDatabase.execSQL.overload("java.lang.String").implementation =
        function (sql) {
          log(`SQL 실행: ${sql}`, "DATABASE");
          return this.execSQL(sql);
        };
      SQLiteDatabase.rawQuery.overload(
        "java.lang.String",
        "[Ljava.lang.String;"
      ).implementation = function (sql, selectionArgs) {
        log(`SQL 쿼리: ${sql}`, "DATABASE");
        if (selectionArgs) {
          log(`쿼리 인자: ${selectionArgs}`, "DATABASE");
        }
        return this.rawQuery(sql, selectionArgs);
      };
    } catch (e) {
      log("SQLite 후킹 실패 (정상적인 경우일 수 있음)", "DEBUG");
    }
    log("파일 시스템 함수 후킹 완료", "INFO");
  } catch (error) {
    log(`파일 시스템 후킹 실패: ${error}`, "ERROR");
  }
}

// --- 동적 로딩 후킹 ---
function hookDynamicLoading() {
  if (!config.hookDynamicLoading) return;
  log("동적 로딩 함수 후킹 시작", "INFO");
  try {
    // DexClassLoader 후킹
    var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
    DexClassLoader.$init.implementation = function (
      dexPath,
      optimizedDirectory,
      librarySearchPath,
      parent
    ) {
      log(`DexClassLoader 로딩: ${dexPath}`, "DYNAMIC");
      log(`최적화 디렉토리: ${optimizedDirectory}`, "DYNAMIC");
      log(`라이브러리 경로: ${librarySearchPath}`, "DYNAMIC");
      return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
    };
    // System.loadLibrary 후킹
    var System = Java.use("java.lang.System");
    System.loadLibrary.implementation = function (libname) {
      log(`Native 라이브러리 로딩: ${libname}`, "DYNAMIC");
      return this.loadLibrary(libname);
    };
    System.load.implementation = function (filename) {
      log(`Native 라이브러리 로딩 (전체 경로): ${filename}`, "DYNAMIC");
      return this.load(filename);
    };
    log("동적 로딩 함수 후킹 완료", "INFO");
  } catch (error) {
    log(`동적 로딩 후킹 실패: ${error}`, "ERROR");
  }
}

// --- 권한 관련 후킹 ---
function hookPermissions() {
  log("권한 관련 함수 후킹 시작", "INFO");
  try {
    // 위험한 권한 사용 감지
    var ActivityCompat = Java.use("androidx.core.app.ActivityCompat");
    ActivityCompat.checkSelfPermission.implementation = function (
      context,
      permission
    ) {
      log(`권한 확인: ${permission}`, "PERMISSION");
      var result = this.checkSelfPermission(context, permission);
      var granted = result === 0 ? "허용됨" : "거부됨";
      log(`권한 상태: ${permission} - ${granted}`, "PERMISSION");
      return result;
    };
    log("권한 관련 함수 후킹 완료", "INFO");
  } catch (error) {
    log(`권한 후킹 실패: ${error}`, "ERROR");
  }
}

// --- 안티 디버깅 우회 ---
function bypassAntiDebugging() {
  log("안티 디버깅 우회 시작", "INFO");
  try {
    // Debug.isDebuggerConnected 우회
    var Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function () {
      log("Debug.isDebuggerConnected 우회됨", "ANTI_DEBUG");
      return false;
    };
    // ApplicationInfo.FLAG_DEBUGGABLE 확인 우회
    var ApplicationInfo = Java.use("android.content.pm.ApplicationInfo");
    ApplicationInfo.flags.getter = function () {
      var flags = this.flags.getter.call(this);
      log(`ApplicationInfo.flags 확인: ${flags}`, "ANTI_DEBUG");
      return flags;
    };
    log("안티 디버깅 우회 완료", "INFO");
  } catch (error) {
    log(`안티 디버깅 우회 실패: ${error}`, "ERROR");
  }
}

// --- Root 탐지 우회 ---
function bypassRootDetection() {
  log("Root 탐지 우회 시작", "INFO");
  try {
    // su 바이너리 파일 존재 확인 우회
    var File = Java.use("java.io.File");
    File.exists.implementation = function () {
      var path = this.getAbsolutePath();
      var result = this.exists();
      // Root 관련 파일 경로면 false 반환
      if (
        path.includes("/su") ||
        path.includes("/system/bin/su") ||
        path.includes("/system/xbin/su") ||
        path.includes("busybox") ||
        path.includes("Superuser.apk")
      ) {
        log(`Root 파일 탐지 우회: ${path}`, "ROOT_BYPASS");
        return false;
      }
      return result;
    };
    // Runtime.exec 명령어 우회
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload("java.lang.String").implementation = function (
      command
    ) {
      log(`Runtime.exec 실행: ${command}`, "ROOT_BYPASS");
      // Root 탐지 명령어면 예외 발생
      if (
        command.includes("su") ||
        command.includes("which su") ||
        command.includes("busybox")
      ) {
        log(`Root 탐지 명령어 차단: ${command}`, "ROOT_BYPASS");
        throw new Error("Command blocked");
      }
      return this.exec(command);
    };
    log("Root 탐지 우회 완료", "INFO");
  } catch (error) {
    log(`Root 탐지 우회 실패: ${error}`, "ERROR");
  }
}

// --- 메인 실행 함수 ---
function main() {
  log("MyMobSF_Analyzer Frida Script 시작", "INFO");
  Java.perform(function () {
    // 각 후킹 기능 실행
    hookCryptography();
    hookNetworking();
    hookFileSystem();
    hookDynamicLoading();
    hookPermissions();
    bypassAntiDebugging();
    bypassRootDetection();
    log("모든 후킹 설정 완료", "INFO");
  });
}
if (Java.available) {
  main();
} else {
  log("Java 런타임을 사용할 수 없습니다", "ERROR");
}

// 메시지 처리
rpc.exports = {
  test: function () {
    return "MyMobSF_Analyzer Frida Script 작동 중";
  },
  enableVerbose: function (enable) {
    config.verbose = enable;
    log(`Verbose 모드: ${enable ? "활성화" : "비활성화"}`, "CONFIG");
  },
  getConfig: function () {
    return config;
  },
};
