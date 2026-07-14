import os
import sys
import time
import subprocess
import webbrowser

def main():
    # Enforce default development API key if not set in environmental context
    if "CADRESEC_API_KEY" not in os.environ:
        os.environ["CADRESEC_API_KEY"] = "admin_dashboard_secret_key"
        print("[LAUNCHER] CADRESEC_API_KEY environment variable not configured. Set to default dev key.")

    # Determine paths and binaries
    cwd = os.path.dirname(os.path.abspath(__file__))
    python_exe = sys.executable
    
    # Configure path safety on Windows for Docker if needed
    if os.name == "nt":
        docker_bin = r"C:\Program Files\Docker\Docker\resources\bin"
        if os.path.exists(docker_bin) and docker_bin not in os.environ.get("Path", ""):
            os.environ["Path"] += ";" + docker_bin

    print(f"[LAUNCHER] Starting Cadresec backend service using {python_exe}...")
    
    # Start the FastAPI server using Uvicorn
    # Note: We run uvicorn as a subprocess
    server_process = None
    try:
        server_process = subprocess.Popen(
            [python_exe, "-m", "uvicorn", "cadresec.api:app", "--host", "127.0.0.1", "--port", "8000"],
            cwd=cwd,
            env=os.environ
        )
        
        # Wait a short duration for the port to bind
        time.sleep(2.5)
        
        # Check if the process died immediately
        if server_process.poll() is not None:
            print("[LAUNCHER] Server failed to start. Exiting.")
            sys.exit(1)

        url = "http://127.0.0.1:8000/"
        print(f"[LAUNCHER] Server is listening. Launching browser to {url}...")
        webbrowser.open(url)

        # Keep launcher alive and pipe interrupts
        try:
            while True:
                if server_process.poll() is not None:
                    print("[LAUNCHER] Server process terminated. Exiting.")
                    break
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[LAUNCHER] Interrupted by operator. Shutting down FastAPI backend...")
            server_process.terminate()
            server_process.wait()
            print("[LAUNCHER] Shutdown complete.")

    except Exception as e:
        print(f"[LAUNCHER] Error running backend: {e}")
        if server_process and server_process.poll() is None:
            server_process.kill()
        sys.exit(1)

if __name__ == "__main__":
    main()
