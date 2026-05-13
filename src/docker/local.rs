use std::io;
use std::path::Path;
use std::process::{Command, ExitStatus};
use std::sync::atomic::Ordering;

use super::shared::*;
use crate::errors::Result;
use crate::extensions::CommandExt;
use crate::file::{PathExt, ToUtf8};
use crate::shell::MessageInfo;
use eyre::Context;
use is_terminal::IsTerminal;

// NOTE: host path must be absolute
fn mount(
    docker: &mut Command,
    host_path: &Path,
    absolute_path: &Path,
    prefix: &str,
    selinux: &str,
) -> Result<()> {
    let mount_path = absolute_path.as_posix_absolute()?;
    docker.args([
        "-v",
        &format!("{}:{prefix}{}{selinux}", host_path.to_utf8()?, mount_path),
    ]);
    Ok(())
}

fn host_kernel_release() -> Result<String> {
    let output = Command::new("uname")
        .arg("-r")
        .output()
        .wrap_err("failed to run uname -r for CROSS_NATIVE_TRACE=1")?;

    if !output.status.success() {
        eyre::bail!(
            "uname -r failed for CROSS_NATIVE_TRACE=1 with status: {}",
            output.status
        );
    }

    let release = String::from_utf8(output.stdout)
        .wrap_err("uname -r output is not valid UTF-8")?
        .trim()
        .to_owned();

    if release.is_empty() {
        eyre::bail!("uname -r returned an empty kernel release");
    }

    Ok(release)
}

fn add_native_trace_ebpf_runtime_args(docker: &mut Command) -> Result<()> {
    if !native_trace_enabled() {
        return Ok(());
    }

    if !cfg!(target_os = "linux") {
        return Ok(());
    }

    for required_path in ["/lib/modules", "/usr/src"] {
        if !Path::new(required_path).exists() {
            eyre::bail!(
                "CROSS_NATIVE_TRACE=1 requires host path to exist: {}",
                required_path
            );
        }
    }

    let kernel_release = host_kernel_release()?;
    let kernel_build = format!("/lib/modules/{kernel_release}/build");
    let kernel_build_path = Path::new(&kernel_build);

    if !kernel_build_path.exists() {
        eyre::bail!(
            "CROSS_NATIVE_TRACE=1 requires host kernel build directory to exist: {}. Install matching kernel-devel/kernel-headers for the running kernel.",
            kernel_build
        );
    }

    let kernel_build_real = kernel_build_path
        .canonicalize()
        .wrap_err_with(|| format!("failed to resolve host kernel build directory: {kernel_build}"))?;

    if !kernel_build_real.exists() {
        eyre::bail!(
            "CROSS_NATIVE_TRACE=1 resolved kernel build directory does not exist: {} -> {}",
            kernel_build,
            kernel_build_real.display()
        );
    }

    docker.args([
        "--privileged",
        "--pid=host",
        "--security-opt",
        "seccomp=unconfined",
        "--ulimit",
        "memlock=-1:-1",
        "-v",
        "/lib/modules:/lib/modules:ro",
        "-v",
        "/usr/src:/usr/src:ro",
    ]);

    // Mount the resolved kernel build directory explicitly as well. This keeps
    // BCC on the normal /lib/modules/<release>/build path and avoids falling
    // back to kheaders extraction, which is unstable when many BCC instances
    // start concurrently.
    docker.arg("-v").arg(format!(
        "{}:{}:ro",
        kernel_build_real.to_utf8()?,
        kernel_build_real.to_utf8()?
    ));

    for path in [
        "/sys/fs/bpf",
        "/sys/kernel/debug",
        "/sys/kernel/tracing",
    ] {
        if Path::new(path).exists() {
            docker.args(["-v", &format!("{path}:{path}:rw")]);
        }
    }

    if Path::new("/sys/kernel/btf").exists() {
        docker.args(["-v", "/sys/kernel/btf:/sys/kernel/btf:ro"]);
    }

    eprintln!(
        "[CROSS_NATIVE_TRACE] enabled: kernel_release={} kernel_build={} kernel_build_real={} mounted /lib/modules, /usr/src, bpf/tracing paths",
        kernel_release,
        kernel_build,
        kernel_build_real.display()
    );

    Ok(())
}

pub(crate) fn run(
    options: DockerOptions,
    paths: DockerPaths,
    args: &[String],
    msg_info: &mut MessageInfo,
) -> Result<Option<ExitStatus>> {
    let engine = &options.engine;
    let toolchain_dirs = paths.directories.toolchain_directories();
    let package_dirs = paths.directories.package_directories();

    let mut cmd = options.command_variant.safe_command();
    cmd.args(args);

    let mut docker = engine.subcommand("run");
    docker.add_userns();
    add_native_trace_ebpf_runtime_args(&mut docker)?;

    // Podman on macOS doesn't support selinux labels, see issue #756
    #[cfg(target_os = "macos")]
    let (selinux, selinux_ro) = if engine.kind.is_podman() {
        ("", ":ro")
    } else {
        (":z", ":z,ro")
    };
    #[cfg(not(target_os = "macos"))]
    let (selinux, selinux_ro) = (":z", ":z,ro");

    options
        .image
        .platform
        .specify_platform(&options.engine, &mut docker);
    docker.add_envvars(&options, toolchain_dirs, msg_info)?;

    docker.add_mounts(
        &options,
        &paths,
        |docker, host, absolute| mount(docker, host, absolute, "", selinux),
        |_| {},
        msg_info,
    )?;

    let container_id = toolchain_dirs.unique_container_identifier(options.target.target())?;
    docker.args(["--name", &container_id]);
    docker.arg("--rm");

    if !native_trace_enabled() {
        docker
            .add_seccomp(engine.kind, &options.target, &paths.metadata)
            .wrap_err("when copying seccomp profile")?;
    }

    docker.add_user_id(engine.is_rootless);

    docker.args([
        "-v",
        &format!(
            "{}:{}{selinux}",
            toolchain_dirs.cargo_host_path()?,
            toolchain_dirs.cargo_mount_path()
        ),
    ]);

    // By default cross hides host-installed Cargo binaries from the container.
    // In native-trace mode we intentionally expose CARGO_HOME/bin so the
    // container can execute cargo-native-trace and native-trace-wrapper.
    if !native_trace_enabled() {
        docker.args(["-v", &format!("{}/bin", toolchain_dirs.cargo_mount_path())]);
    }

    let host_root = paths.mount_finder.find_mount_path(package_dirs.host_root());
    docker.args([
        "-v",
        &format!(
            "{}:{}{selinux}",
            host_root.to_utf8()?,
            package_dirs.mount_root()
        ),
    ]);

    let sysroot = paths
        .mount_finder
        .find_mount_path(toolchain_dirs.get_sysroot());
    docker
        .args([
            "-v",
            &format!(
                "{}:{}{selinux_ro}",
                sysroot.to_utf8()?,
                toolchain_dirs.sysroot_mount_path()
            ),
        ])
        .args([
            "-v",
            &format!("{}:/target{selinux}", package_dirs.target().to_utf8()?),
        ]);
    docker.add_cwd(&paths)?;

    // When running inside NixOS or using Nix packaging we need to add the Nix
    // Store to the running container so it can load the needed binaries.
    if let Some(nix_store) = toolchain_dirs.nix_store() {
        docker.args([
            "-v",
            &format!(
                "{}:{}{selinux}",
                nix_store.to_utf8()?,
                nix_store.as_posix_absolute()?
            ),
        ]);
    }

    if io::stdin().is_terminal() && io::stdout().is_terminal() && io::stderr().is_terminal() {
        docker.arg("-t");
    }

    if options.interactive {
        docker.arg("-i");
    }

    let mut image_name = options.image.name.clone();
    if options.needs_custom_image() {
        image_name = options
            .custom_image_build(&paths, msg_info)
            .wrap_err("when building custom image")?;
    }

    ChildContainer::create(engine.clone(), container_id)?;
    if msg_info.should_fail() {
        return Ok(None);
    }

    let status = docker
        .arg(&image_name)
        .add_build_command(toolchain_dirs, &cmd)
        .run_and_get_status(msg_info, false);

    // `cargo` generally returns 0 or 101 on completion, but isn't guaranteed
    // to. `ExitStatus::code()` may be None if a signal caused the process to
    // terminate or it may be a known interrupt return status (130, 137, 143).
    // simpler: just test if the program termination handler was called.
    // SAFETY: an atomic load.
    let is_terminated = crate::errors::TERMINATED.load(Ordering::SeqCst);
    if !is_terminated {
        ChildContainer::exit_static();
    }

    status.map(Some)
}
