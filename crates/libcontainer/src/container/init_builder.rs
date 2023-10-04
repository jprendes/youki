use nix::unistd;
use oci_spec::runtime::Spec;
use std::{
    fs,
    path::{Path, PathBuf},
    rc::Rc,
};
use user_ns::UserNamespaceConfig;

use crate::{
    apparmor,
    config::YoukiConfig,
    error::{ErrInvalidSpec, LibcontainerError, MissingSpecError},
    notify_socket::NOTIFY_FILE,
    process::args::ContainerType,
    tty, user_ns, utils,
};

use super::{
    builder::ContainerBuilder, builder_impl::ContainerBuilderImpl, Container, ContainerStatus,
};

// Builder that can be used to configure the properties of a new container
pub struct InitContainerBuilder {
    base: ContainerBuilder,
    bundle: PathBuf,
    use_systemd: bool,
    detached: bool,
}

impl InitContainerBuilder {
    /// Generates the base configuration for a new container from which
    /// configuration methods can be chained
    pub(super) fn new(builder: ContainerBuilder, bundle: PathBuf) -> Self {
        Self {
            base: builder,
            bundle,
            use_systemd: true,
            detached: true,
        }
    }

    /// Sets if systemd should be used for managing cgroups
    pub fn with_systemd(mut self, should_use: bool) -> Self {
        self.use_systemd = should_use;
        self
    }

    pub fn with_detach(mut self, detached: bool) -> Self {
        self.detached = detached;
        self
    }

    /// Creates a new container
    pub fn build(self) -> Result<Container, LibcontainerError> {
        log::info!("YYYYYY libcontainer::build 1, {:?}", self.bundle);
        let spec = self.load_spec()?;
        log::info!("YYYYYY libcontainer::build 2, {:?}", self.bundle);
        let container_dir = self.create_container_dir()?;
        log::info!("YYYYYY libcontainer::build 3, {:?}", self.bundle);

        let mut container = self.create_container_state(&container_dir)?;
        log::info!("YYYYYY libcontainer::build 4, {:?}", self.bundle);
        container
            .set_systemd(self.use_systemd)
            .set_annotations(spec.annotations().clone());
        log::info!("YYYYYY libcontainer::build 5, {:?}", self.bundle);

        unistd::chdir(&container_dir).map_err(|err| {
            tracing::error!(
                ?container_dir,
                ?err,
                "failed to chdir into the container directory"
            );
            LibcontainerError::OtherSyscall(err)
        })?;
        log::info!("YYYYYY libcontainer::build 6, {:?}", self.bundle);
        let notify_path = container_dir.join(NOTIFY_FILE);
        log::info!("YYYYYY libcontainer::build 7, {:?}", self.bundle);
        // convert path of root file system of the container to absolute path
        let rootfs = fs::canonicalize(spec.root().as_ref().ok_or(MissingSpecError::Root)?.path())
            .map_err(LibcontainerError::OtherIO)?;
        log::info!("YYYYYY libcontainer::build 8, {:?}", self.bundle);

        // if socket file path is given in commandline options,
        // get file descriptors of console socket
        let csocketfd = if let Some(console_socket) = &self.base.console_socket {
            log::info!("YYYYYY libcontainer::build 9, {:?}", self.bundle);
            Some(tty::setup_console_socket(
                &container_dir,
                console_socket,
                "console-socket",
            )?)
        } else {
            log::info!("YYYYYY libcontainer::build 10, {:?}", self.bundle);
            None
        };
        log::info!("YYYYYY libcontainer::build 11, {:?}", self.bundle);

        let user_ns_config = UserNamespaceConfig::new(&spec)?;

        log::info!("YYYYYY libcontainer::build 12, {:?}", self.bundle);

        let config = YoukiConfig::from_spec(&spec, container.id(), user_ns_config.is_some())?;

        log::info!("YYYYYY libcontainer::build 13, {:?}", self.bundle);
        config.save(&container_dir).map_err(|err| {
            tracing::error!(?container_dir, "failed to save config: {}", err);
            err
        })?;

        log::info!("YYYYYY libcontainer::build 14, {:?}", self.bundle);

        let mut builder_impl = ContainerBuilderImpl {
            container_type: ContainerType::InitContainer,
            syscall: self.base.syscall,
            container_id: self.base.container_id,
            pid_file: self.base.pid_file,
            console_socket: csocketfd,
            use_systemd: self.use_systemd,
            spec: Rc::new(spec),
            rootfs,
            user_ns_config,
            notify_path,
            container: Some(container.clone()),
            preserve_fds: self.base.preserve_fds,
            detached: self.detached,
            executor: self.base.executor,
        };

        log::info!("YYYYYY libcontainer::build 15, {:?}", self.bundle);

        builder_impl.create()?;

        log::info!("YYYYYY libcontainer::build 16, {:?}", self.bundle);

        container.refresh_state()?;

        log::info!("YYYYYY libcontainer::build 17, {:?}", self.bundle);

        Ok(container)
    }

    fn create_container_dir(&self) -> Result<PathBuf, LibcontainerError> {
        let container_dir = self.base.root_path.join(&self.base.container_id);
        tracing::debug!("container directory will be {:?}", container_dir);

        if container_dir.exists() {
            tracing::error!(id = self.base.container_id, dir = ?container_dir, "container already exists");
            return Err(LibcontainerError::Exist);
        }

        std::fs::create_dir_all(&container_dir).map_err(|err| {
            tracing::error!(
                ?container_dir,
                "failed to create container directory: {}",
                err
            );
            LibcontainerError::OtherIO(err)
        })?;

        Ok(container_dir)
    }

    fn load_spec(&self) -> Result<Spec, LibcontainerError> {
        let source_spec_path = self.bundle.join("config.json");
        let mut spec = Spec::load(source_spec_path)?;
        Self::validate_spec(&spec)?;

        spec.canonicalize_rootfs(&self.bundle).map_err(|err| {
            tracing::error!(bundle = ?self.bundle, "failed to canonicalize rootfs: {}", err);
            err
        })?;

        Ok(spec)
    }

    fn validate_spec(spec: &Spec) -> Result<(), LibcontainerError> {
        let version = spec.version();
        if !version.starts_with("1.") {
            tracing::error!(
                "runtime spec has incompatible version '{}'. Only 1.X.Y is supported",
                spec.version()
            );
            Err(ErrInvalidSpec::UnsupportedVersion)?;
        }

        if let Some(process) = spec.process() {
            if let Some(profile) = process.apparmor_profile() {
                let apparmor_is_enabled = apparmor::is_enabled().map_err(|err| {
                    tracing::error!(?err, "failed to check if apparmor is enabled");
                    LibcontainerError::OtherIO(err)
                })?;
                if !apparmor_is_enabled {
                    tracing::error!(?profile,
                        "apparmor profile exists in the spec, but apparmor is not activated on this system");
                    Err(ErrInvalidSpec::AppArmorNotEnabled)?;
                }
            }

            if let Some(io_priority) = process.io_priority() {
                let priority = io_priority.priority();
                let iop_class_res = serde_json::to_string(&io_priority.class());
                match iop_class_res {
                    Ok(iop_class) => {
                        if !(0..=7).contains(&priority) {
                            tracing::error!(?priority, "io priority '{}' not between 0 and 7 (inclusive), class '{}' not in (IO_PRIO_CLASS_RT,IO_PRIO_CLASS_BE,IO_PRIO_CLASS_IDLE)",priority, iop_class);
                            Err(ErrInvalidSpec::IoPriority)?;
                        }
                    }
                    Err(e) => {
                        tracing::error!(?priority, ?e, "failed to parse io priority class");
                        Err(ErrInvalidSpec::IoPriority)?;
                    }
                }
            }
        }

        utils::validate_spec_for_new_user_ns(spec)?;

        Ok(())
    }

    fn create_container_state(&self, container_dir: &Path) -> Result<Container, LibcontainerError> {
        let container = Container::new(
            &self.base.container_id,
            ContainerStatus::Creating,
            None,
            &self.bundle,
            container_dir,
        )?;
        container.save()?;
        Ok(container)
    }
}
