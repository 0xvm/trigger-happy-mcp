import os
import time
import uuid
import threading
import subprocess
import shlex
from collections import deque
from typing import Annotated, Optional, TypedDict

from zeromcp import McpServer, McpToolError

# --- Rich logging setup ---
import logging
from rich.logging import RichHandler

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",         # RichHandler adds time/level formatting
    datefmt="[%H:%M:%S]",
    handlers=[RichHandler(rich_tracebacks=True)],
)

log = logging.getLogger("mcp-server")

# --- MCP server setup ---

mcp = McpServer("my-http-server")
stop_event = threading.Event()

# Base directory to store job logs
JOB_BASE_DIR = os.environ.get("MCP_JOB_DIR", "/tmp/mcp-jobs")


def log_tool_call(tool_name: str, **kwargs) -> None:
    """Small helper to log tool calls with their arguments."""
    pretty_args = ", ".join(f"{k}={v!r}" for k, v in kwargs.items())
    log.info(f"[tool:{tool_name}] called with {pretty_args}")


# ---------- Simple greet tool ----------

@mcp.tool
def greet(
    name: Annotated[str, "Name to greet"],
    age: Annotated[int | None, "Age of the person"] = None,
) -> str:
    """Generate a greeting message."""
    log_tool_call("greet", name=name, age=age)
    if age is not None:
        result = f"Hello, {name}! You are {age} years old."
    else:
        result = f"Hello, {name}!"
    log.info(f"[tool:greet] result -> {result!r}")
    return result


# ---------- Job types & registry ----------

class ShellJob(TypedDict, total=False):
    id: Annotated[str, "Job ID"]
    command: Annotated[str, "Command that was executed"]
    use_shell: Annotated[bool, "Whether shell=True was used"]
    status: Annotated[str, "pending|running|done|error"]
    started_at: Annotated[float, "Unix timestamp when started"]
    finished_at: Annotated[Optional[float], "Unix timestamp when finished"]
    exit_code: Annotated[Optional[int], "Process exit code"]

    # Instead of full stdout/stderr, we store:
    stdout_tail: Annotated[Optional[str], "Last N lines of stdout"]
    stderr_tail: Annotated[Optional[str], "Last N lines of stderr"]
    stdout_path: Annotated[Optional[str], "Path to full stdout log file"]
    stderr_path: Annotated[Optional[str], "Path to full stderr log file"]
    stdout_len: Annotated[Optional[int], "Total stdout length in characters"]
    stderr_len: Annotated[Optional[int], "Total stderr length in characters"]

    error: Annotated[Optional[str], "Error message if status=error"]
    duration_sec: Annotated[Optional[float], "Execution time in seconds"]


_JOBS: dict[str, ShellJob] = {}
_JOBS_LOCK = threading.Lock()


def _update_job(job_id: str, **fields) -> None:
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if not job:
            return
        job.update(fields)


def _run_shell_job(
    job_id: str,
    command: str,
    use_shell: bool,
    env: Optional[dict[str, str]],
    cwd: Optional[str],
    tail_lines: int = 20,
) -> None:
    """
    Background worker that actually runs the command.

    While the process runs, stdout/stderr are:
      - streamed to logs line-by-line
      - written to per-job log files on disk
      - a small tail is kept in memory & stored in the job record
    """
    log.info(f"[job {job_id}] starting command (use_shell={use_shell}): {command!r}")

    # Create job-specific directory and log file paths
    job_dir = os.path.join(JOB_BASE_DIR, job_id)
    os.makedirs(job_dir, exist_ok=True)
    stdout_path = os.path.join(job_dir, "stdout.log")
    stderr_path = os.path.join(job_dir, "stderr.log")

    with _JOBS_LOCK:
        job = _JOBS[job_id]
        job["status"] = "running"
        job["started_at"] = time.time()
        job["stdout_path"] = stdout_path
        job["stderr_path"] = stderr_path
        job["stdout_tail"] = ""
        job["stderr_tail"] = ""

    # Build environment
    effective_env = os.environ.copy()
    if env:
        effective_env.update(env)

    if use_shell:
        popen_args = {
            "args": command,
            "shell": True,
        }
        log.info(f"[job {job_id}] using shell=True for command")
    else:
        args = shlex.split(command)
        popen_args = {
            "args": args,
            "shell": False,
        }
        log.info(f"[job {job_id}] using exec args={args!r}")

    popen_kwargs = dict(
        cwd=cwd or None,
        env=effective_env,
        text=True,
        bufsize=1,      # line-buffered
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    popen_args.update(popen_kwargs)

    # We keep only a tail in memory, full logs go to files
    stdout_tail_deque: deque[str] = deque(maxlen=tail_lines)
    stderr_tail_deque: deque[str] = deque(maxlen=tail_lines)

    # Open log files
    try:
        f_stdout = open(stdout_path, "w", encoding="utf-8", errors="replace")
        f_stderr = open(stderr_path, "w", encoding="utf-8", errors="replace")
    except Exception as e:
        log.exception(f"[job {job_id}] failed to open log files")
        _update_job(
            job_id,
            status="error",
            error=f"Failed to open log files: {e}",
            finished_at=time.time(),
            duration_sec=0.0,
        )
        return

    def _reader(stream, is_stdout: bool) -> None:
        """
        Read lines from stream, log, write to file, update tail in job.
        """
        prefix = "stdout" if is_stdout else "stderr"
        tail_deque = stdout_tail_deque if is_stdout else stderr_tail_deque
        file_handle = f_stdout if is_stdout else f_stderr
        tail_key = "stdout_tail" if is_stdout else "stderr_tail"

        for line in stream:
            if not line:
                break
            line_stripped = line.rstrip("\n")

            # Stream to logs
            if is_stdout:
                log.info(f"[job {job_id}][{prefix}] {line_stripped}")
            else:
                log.warning(f"[job {job_id}][{prefix}] {line_stripped}")

            # Write full output to log file
            file_handle.write(line)
            file_handle.flush()

            # Maintain tail in memory
            tail_deque.append(line_stripped)

            # Update job record with latest tail
            with _JOBS_LOCK:
                job = _JOBS.get(job_id)
                if job:
                    job[tail_key] = "\n".join(tail_deque)

        stream.close()

    start = time.time()
    try:
        proc = subprocess.Popen(**popen_args)
    except Exception as e:
        log.exception(f"[job {job_id}] failed to start process")
        f_stdout.close()
        f_stderr.close()
        _update_job(
            job_id,
            status="error",
            error=f"Failed to start command: {e}",
            finished_at=time.time(),
            duration_sec=time.time() - start,
        )
        return

    threads: list[threading.Thread] = []
    if proc.stdout is not None:
        t_out = threading.Thread(target=_reader, args=(proc.stdout, True), daemon=True)
        threads.append(t_out)
        t_out.start()
    if proc.stderr is not None:
        t_err = threading.Thread(target=_reader, args=(proc.stderr, False), daemon=True)
        threads.append(t_err)
        t_err.start()

    for t in threads:
        t.join()

    proc.wait()
    duration = time.time() - start

    # Make sure files are closed
    f_stdout.close()
    f_stderr.close()

    # Compute total lengths (in characters)
    stdout_len = os.path.getsize(stdout_path) if os.path.exists(stdout_path) else 0
    stderr_len = os.path.getsize(stderr_path) if os.path.exists(stderr_path) else 0

    status = "done" if proc.returncode == 0 else "error"
    log.info(
        f"[job {job_id}] finished with exit={proc.returncode}, "
        f"status={status}, duration={duration:.1f}s, "
        f"stdout_len={stdout_len}, stderr_len={stderr_len}"
    )

    _update_job(
        job_id,
        status=status,
        exit_code=proc.returncode,
        finished_at=time.time(),
        duration_sec=duration,
        stdout_len=stdout_len,
        stderr_len=stderr_len,
        error=None if status == "done" else "Process exited with non-zero status",
    )


# ---------- MCP tools: start & get jobs ----------

@mcp.tool
def start_shell_job(
    command: Annotated[
        str,
        "Command to run. For complex commands (pipes, redirects, nmap, etc.), set use_shell=True."
    ],
    use_shell: Annotated[
        bool,
        "Run via system shell (shell=True). Needed for pipes/redirects/etc."
    ] = True,
    env: Annotated[
        dict[str, str] | None,
        "Extra environment variables for this command"
    ] = None,
    cwd: Annotated[
        str | None,
        "Working directory for the command"
    ] = None,
) -> ShellJob:
    """
    Start a long-running shell command as a background job.

    Full stdout/stderr go to log files on disk.
    The job record exposes:
      - stdout_tail / stderr_tail (last lines)
      - stdout_path / stderr_path (paths to full logs)
    """
    log_tool_call("start_shell_job", command=command, use_shell=use_shell, cwd=cwd)

    if not command.strip():
        raise McpToolError("Command must not be empty")

    job_id = str(uuid.uuid4())

    job: ShellJob = {
        "id": job_id,
        "command": command,
        "use_shell": use_shell,
        "status": "pending",
        "started_at": time.time(),
        "finished_at": None,
        "exit_code": None,
        "stdout_tail": "",
        "stderr_tail": "",
        "stdout_path": None,
        "stderr_path": None,
        "stdout_len": None,
        "stderr_len": None,
        "error": None,
        "duration_sec": None,
    }

    with _JOBS_LOCK:
        _JOBS[job_id] = job

    worker = threading.Thread(
        target=_run_shell_job,
        args=(job_id, command, use_shell, env, cwd),
        daemon=True,
    )
    worker.start()

    log.info(f"[tool:start_shell_job] created job {job_id}")
    return job


@mcp.tool
def get_shell_job(
    job_id: Annotated[str, "Job ID returned by start_shell_job"]
) -> ShellJob:
    """
    Get the current status and result (if finished) of a shell job.

    While the job is running, stdout_tail/stderr_tail will contain the
    last N lines seen so far. Full logs live in the stdout_path/stderr_path
    files on disk.
    """
    log_tool_call("get_shell_job", job_id=job_id)

    with _JOBS_LOCK:
        job = _JOBS.get(job_id)

    if not job:
        raise McpToolError(f"No job found with id={job_id}")

    # Return a shallow copy so we don't accidentally mutate the stored job
    return dict(job)


@mcp.tool
def list_shell_jobs() -> list[ShellJob]:
    """List all known shell jobs (metadata + tails, not full logs)."""
    log_tool_call("list_shell_jobs")
    with _JOBS_LOCK:
        return [dict(job) for job in _JOBS.values()]


# ---------- Server startup ----------

if __name__ == "__main__":
    log.info("Starting MCP server on http://0.0.0.0:12983/mcp")
    os.makedirs(JOB_BASE_DIR, exist_ok=True)
    mcp.serve("0.0.0.0", 12983)

    try:
        stop_event.wait()
    except KeyboardInterrupt:
        log.info("Stopping MCP server...")
        mcp.stop()
        log.info("MCP server stopped.")

