@echo off
rem ---------------------------------------------------------------------------
rem One-click launcher for Windows. The counterpart of run.sh, kept in step with
rem it deliberately so a site can be supported over the phone with one set of
rem instructions.
rem
rem This is the file an operator double-clicks. It has to either start the
rem service or leave a window open saying, in one sentence, what stopped it --
rem so every failure path below ends in a message and a `pause`, and the success
rem path never pauses.
rem
rem Messages are written without Turkish diacritics on purpose. A .bat file is
rem read by cmd.exe in the console's active code page, which on a Turkish
rem Windows is 857 and on an English one 437; a UTF-8 source byte then prints as
rem mojibake. `chcp 65001` below fixes the *child* process (Python's output),
rem which is what actually matters, but this file's own literals stay ASCII so
rem they are legible whatever the console was set to.
rem ---------------------------------------------------------------------------

setlocal EnableExtensions

rem UTF-8 for everything this script starts. Without it the service's Turkish
rem log lines go through the console's legacy code page and either come out
rem mangled or, when a character has no mapping at all, raise a
rem UnicodeEncodeError inside the logging handler -- a crash whose cause looks
rem nothing like "the console cannot spell this word".
chcp 65001 >nul 2>&1
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

rem The repo root, not wherever the shortcut was invoked from. The trailing "."
rem matters: %~dp0 already ends in a backslash, and "C:\path\" is a quoting
rem hazard, while "C:\path\." is unambiguous.
cd /d "%~dp0."
if errorlevel 1 (
    echo [x] Proje klasorune gecilemedi: %~dp0
    pause
    exit /b 1
)

rem Version range kept in step with `requires-python` in pyproject.toml. Both
rem ends are enforced: too old and the install fails, too new and the ML wheels
rem (torch, and easyocr's dependency chain) are not published yet.
set "PY_RANGE=3.11 - 3.13"

rem ---------------------------------------------------------------------------
rem 1. Virtual environment
rem ---------------------------------------------------------------------------

rem An existing venv\ wins because that is the name the Makefile hardcodes
rem (VENV ?= venv): a checkout already set up that way must not silently grow a
rem second, half-installed environment beside the first. Anything else gets
rem .venv\, which editors and tooling autodetect. Both are gitignored.
set "VENV_DIR=.venv"
if exist "venv\pyvenv.cfg" set "VENV_DIR=venv"
set "VENV_PY=%VENV_DIR%\Scripts\python.exe"

rem The environment that will actually run the service is checked first, and a
rem machine that already has a good one needs no system interpreter at all.
rem Looking for a system Python first would refuse to start a perfectly good
rem 3.12 virtualenv on a host whose default Python has moved on to an
rem unsupported release -- and that interpreter is not the one that would run
rem anything anyway.
if not exist "%VENV_PY%" goto :make_venv

call :version_ok "%VENV_PY%"
if not errorlevel 1 goto :venv_ready

echo.
echo [x] "%VENV_DIR%" icindeki Python surumu desteklenmiyor.
call :show_version "%VENV_PY%"
echo     Desteklenen aralik: %PY_RANGE%
echo.
echo     "%VENV_DIR%" klasorunu silip run.bat dosyasini yeniden calistirin.
echo.
pause
exit /b 1

rem ---------------------------------------------------------------------------
rem 2. No usable environment yet: find an interpreter and build one
rem ---------------------------------------------------------------------------

rem The `py` launcher is tried before PATH: it is what python.org's installer
rem registers, it finds interpreters that were never added to PATH, and it can
rem be asked for one exact version. The versioned probes come first because
rem `py -3` picks the *newest* 3.x, which on a machine that has already taken a
rem newer release would be one this project cannot use -- while the supported
rem one usually sits right there beside it.
rem
rem Bare `python` is last, and note that on a machine with no Python it is
rem usually still present as the Microsoft Store stub. That is exactly why every
rem probe *runs* the interpreter instead of testing for the file: the stub exits
rem non-zero without opening the Store.
:make_venv
set "PY_CMD="
call :try_python "py -3.13"
call :try_python "py -3.12"
call :try_python "py -3.11"
call :try_python "py -3"
call :try_python "python"
if defined PY_CMD goto :have_python

rem Nothing usable. Say which of the two problems it is, because "install
rem Python" is unhelpful advice to somebody who already has one.
set "PY_ANY="
py -3 -c "import sys" >nul 2>&1
if not errorlevel 1 set "PY_ANY=py -3"
if defined PY_ANY goto :wrong_version
python -c "import sys" >nul 2>&1
if not errorlevel 1 set "PY_ANY=python"
if defined PY_ANY goto :wrong_version

echo.
echo [x] Python bulunamadi.
goto :python_help

:wrong_version
echo.
echo [x] Kurulu Python surumu uygun degil.
call :show_version "%PY_ANY%"
goto :python_help

:python_help
echo.
echo     Bu proje Python %PY_RANGE% gerektiriyor.
echo.
echo     1. https://www.python.org/downloads/ adresinden Python 3.12 indirin.
echo     2. Kurulum sirasinda "Add Python to PATH" kutusunu MUTLAKA isaretleyin.
echo     3. Bu pencereyi kapatip run.bat dosyasini yeniden calistirin.
echo.
pause
exit /b 1

:have_python
call :show_version "%PY_CMD%"
echo ==^> Sanal ortam olusturuluyor: %VENV_DIR%\
%PY_CMD% -m venv "%VENV_DIR%"
if errorlevel 1 goto :venv_failed
if exist "%VENV_PY%" goto :venv_ready

:venv_failed
echo.
echo [x] Sanal ortam olusturulamadi: %VENV_DIR%
echo     Bu klasore yazma izniniz oldugundan emin olun.
echo.
pause
exit /b 1

rem ---------------------------------------------------------------------------
rem 3. Dependencies, guarded by a content hash
rem ---------------------------------------------------------------------------

rem Installing on every launch would add tens of seconds to a start that should
rem be instant; skipping unconditionally would leave a site running last month's
rem requirements after a `git pull`. The sentinel holds a SHA-256 of
rem requirements.txt + pyproject.toml, so "stale" is answered by content.
rem
rem A hash rather than a modification time because batch cannot compare file
rem times without help anyway, and because git does not preserve mtimes: a fresh
rem clone would look either always-stale or never-stale depending on the order
rem the files happened to be written.
rem
rem The check and the write are both done by an inline `python -c` that takes
rem the sentinel and the inputs as argv and answers with its exit code. That
rem keeps the whole thing out of batch string handling -- no `for /f` capture,
rem no temporary file, and nothing that a space or a non-ASCII character in the
rem repository path can break.

:venv_ready
set "SENTINEL=%VENV_DIR%\.deps_installed"

"%VENV_PY%" -c "import hashlib, pathlib, sys; d = hashlib.sha256(); [(d.update(n.encode()), d.update(pathlib.Path(n).read_bytes() if pathlib.Path(n).is_file() else b'')) for n in sys.argv[2:]]; s = pathlib.Path(sys.argv[1]); sys.exit(0 if s.is_file() and s.read_text().strip() == d.hexdigest() else 1)" "%SENTINEL%" "requirements.txt" "pyproject.toml"
if not errorlevel 1 goto :deps_ok

rem Written as two labels rather than an if/else block on purpose: the `^>` in
rem the arrow is an escaped redirection character, and escaping inside a
rem parenthesised block is one of the corners of batch that behaves differently
rem depending on how the block was entered. At the top level it simply works.
echo.
if exist "%SENTINEL%" goto :deps_stale
echo ==^> Bagimliliklar kuruluyor. Ilk calistirmada birkac dakika surebilir...
goto :deps_install

:deps_stale
echo ==^> Bagimliliklar degismis, guncelleniyor. Bu birkac dakika surebilir...

:deps_install
echo.

rem Deleted before the install and never written after a failure: a sentinel
rem left behind by an interrupted install would claim an environment is complete
rem when it is not, and the next launch would start a service with half its
rem packages.
del /f /q "%SENTINEL%" >nul 2>&1

"%VENV_PY%" -m pip install --upgrade pip
if errorlevel 1 goto :deps_failed

rem PyTorch comes from PyTorch's own CPU index on Windows, before
rem requirements.txt is touched. The wheel PyPI serves for win_amd64 is not
rem self-contained: it links libiomp5md.dll and the rest of the Intel OpenMP
rem runtime without shipping them, so on a clean Windows 11 -- one that has
rem never had a redistributable installed by some other program -- the very
rem first `import torch` dies with "[WinError 127] The specified procedure
rem could not be found ... shm.dll". That is a loader error naming a file that
rem is present, so it reads as a corrupt install; it is a missing sibling DLL.
rem The wheels on download.pytorch.org bundle the runtime and just work.
rem
rem Order matters. This has to run *before* `pip install -r requirements.txt`:
rem torch is pinned there too, so installing it here first leaves that
rem requirement already satisfied and pip moves on, while the reverse order
rem downloads a quarter of a gigabyte from PyPI and then finds nothing left to
rem do. Nothing is pinned here on purpose -- requirements.txt owns the version
rem range, and the install below enforces it on whatever this brought in.
rem
rem Not fatal on its own. A site behind a proxy that reaches PyPI but not
rem download.pytorch.org should still get an environment; the check after the
rem install is what decides whether torch actually works.
set "TORCH_CPU_INDEX=https://download.pytorch.org/whl/cpu"
"%VENV_PY%" -m pip install torch torchvision --index-url %TORCH_CPU_INDEX%
if errorlevel 1 echo [!] PyTorch CPU deposuna erisilemedi; PyPI surumu denenecek.

"%VENV_PY%" -m pip install -r requirements.txt
if errorlevel 1 goto :deps_failed
"%VENV_PY%" -m pip install -e .
if errorlevel 1 goto :deps_failed

rem Proving it, rather than assuming it. This catches the two ways the step
rem above can still leave a broken environment: an install that predates this
rem launcher and already has the PyPI wheel in place (pip sees the requirement
rem satisfied and does nothing), and a torch that requirements.txt pulled back
rem to a PyPI build to satisfy its version range. Both look like a completed
rem install and fail hours later at the first frame.
rem
rem The cost is one `import torch` on an install that already ran, which is
rem seconds, and it is paid only on this path -- an up-to-date environment
rem skips the whole section.
"%VENV_PY%" -c "import torch, torchvision" >nul 2>&1
if not errorlevel 1 goto :torch_ok

echo.
echo ==^> PyTorch calismiyor, CPU tekerlekleri yeniden kuruluyor...
"%VENV_PY%" -m pip install --force-reinstall torch torchvision --index-url %TORCH_CPU_INDEX%
if errorlevel 1 goto :torch_failed
"%VENV_PY%" -c "import torch, torchvision" >nul 2>&1
if errorlevel 1 goto :torch_failed

:torch_ok

"%VENV_PY%" -c "import hashlib, pathlib, sys; d = hashlib.sha256(); [(d.update(n.encode()), d.update(pathlib.Path(n).read_bytes() if pathlib.Path(n).is_file() else b'')) for n in sys.argv[2:]]; pathlib.Path(sys.argv[1]).write_text(d.hexdigest())" "%SENTINEL%" "requirements.txt" "pyproject.toml"

rem Directories, signing keys, a local licence and a .env. Idempotent, and
rem deliberately non-fatal: the API's degraded-mode contract means it starts and
rem reports what is missing, which is more use to whoever is standing at the
rem gate than a launcher that refuses to run.
"%VENV_PY%" scripts\setup_dev.py
if errorlevel 1 echo [!] scripts\setup_dev.py basarisiz oldu; servis eksik yapilandirmayla baslayacak.
goto :dirs

:torch_failed
echo.
echo [x] PyTorch bu makinede calistirilamiyor.
echo     Genellikle Visual C++ Redistributable eksik oldugunda gorulur:
echo     https://aka.ms/vs/17/release/vc_redist.x64.exe adresinden kurup
echo     run.bat dosyasini yeniden calistirin.
echo.
pause
exit /b 1

:deps_failed
echo.
echo [x] Bagimliliklar kurulamadi.
echo     Internet baglantisini kontrol edip run.bat dosyasini yeniden calistirin.
echo.
pause
exit /b 1

:deps_ok
echo     Bagimliliklar guncel.

rem ---------------------------------------------------------------------------
rem 4. Runtime directories
rem ---------------------------------------------------------------------------

rem The application creates these itself, but doing it here means a permission
rem problem on the data folder surfaces now, with a path in the message, instead
rem of as a swallowed warning on the snapshot writer's thread an hour later.
:dirs
if not exist "data" mkdir "data"
if not exist "data\snapshots" mkdir "data\snapshots"

rem ---------------------------------------------------------------------------
rem 5. Launch
rem ---------------------------------------------------------------------------

echo.
echo ==^> LPR servisi baslatiliyor
echo     Panel:    http://localhost:8000
echo     Durdurma: Ctrl+C
echo.

rem Host and port come from config.yaml / .env (api.host, api.port); the URL
rem above is the shipped default.
"%VENV_PY%" -m lpr.api.main
set "EXIT_CODE=%ERRORLEVEL%"

rem Ctrl+C on Windows terminates the child with STATUS_CONTROL_C_EXIT
rem (0xC000013A), which cmd surfaces as -1073741510. uvicorn has already run its
rem graceful shutdown by then, so that is a clean stop, not a failure -- treating
rem it as one would end every normal session with an error box.
rem
rem cmd may still print "Terminate batch job (Y/N)?" after a Ctrl+C. That prompt
rem cannot be suppressed from inside a .bat file, and it is harmless here: the
rem server is the last command in the script, so either answer leaves nothing
rem undone.
if "%EXIT_CODE%"=="-1073741510" set "EXIT_CODE=0"
if "%EXIT_CODE%"=="0" goto :done

echo.
echo [x] Servis %EXIT_CODE% kodu ile sonlandi.
echo     Ayrinti icin yukaridaki mesajlari ve data\lpr.log dosyasini inceleyin.
echo.
pause

:done
endlocal & exit /b %EXIT_CODE%

rem ---------------------------------------------------------------------------
rem Subroutines
rem ---------------------------------------------------------------------------

rem Probe one interpreter and claim it if it is in range. Skips its work once
rem PY_CMD is set, so the callers above read as a plain priority list rather
rem than a chain of gotos.
rem
rem The range test enumerates the supported minors instead of comparing them, so
rem the command carries no `<` or `>`: cmd does not treat a redirection
rem character inside double quotes as one, but a launcher is the wrong place to
rem depend on that.
:try_python
if defined PY_CMD goto :eof
%~1 -c "import sys; sys.exit(0 if sys.version_info[:2] in ((3, 11), (3, 12), (3, 13)) else 1)" >nul 2>&1
if not errorlevel 1 set "PY_CMD=%~1"
goto :eof

rem Exit code 0 when the given interpreter is in range. Used for the venv, where
rem the answer decides between "go" and a message naming the version.
:version_ok
"%~1" -c "import sys; sys.exit(0 if sys.version_info[:2] in ((3, 11), (3, 12), (3, 13)) else 1)" >nul 2>&1
goto :eof

rem Print the version of an interpreter, quietly doing nothing if it will not
rem run. Only ever decorates a message, so it must never be the thing that
rem fails.
:show_version
for /f "delims=" %%V in ('%~1 -c "import sys; print(sys.version.split()[0])" 2^>nul') do echo     Python %%V
goto :eof
