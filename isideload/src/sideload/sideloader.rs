use crate::{
    dev::{
        app_groups::AppGroupsApi,
        app_ids::{AppIdsApi, Profile},
        developer_session::DeveloperSession,
        devices::DevicesApi,
        teams::{DeveloperTeam, TeamsApi},
    },
    sideload::{
        TeamSelection,
        application::{Application, SpecialApp},
        builder::{ExtensionsBehavior, ExtensionsBehaviorSelection, MaxCertsBehavior},
        cert_identity::CertificateIdentity,
        sign,
    },
    util::{
        callbacks::{ExtensionsBehaviorCallback, MaxCertsCallback},
        device::IdeviceInfo,
        storage::SideloadingStorage,
    },
};

use std::path::PathBuf;

use apple_codesign_quick::ProvisioningProfile;
use idevice::provider::IdeviceProvider;
use plist::Dictionary;
use rootcause::{option_ext::OptionExt, prelude::*};
use tracing::info;

pub struct Sideloader<C: MaxCertsCallback, E: ExtensionsBehaviorCallback> {
    team_selection: TeamSelection,
    storage: Box<dyn SideloadingStorage>,
    dev_session: DeveloperSession,
    machine_name: String,
    apple_email: String,
    max_certs_behavior: MaxCertsBehavior<C>,
    extensions_behavior: ExtensionsBehaviorSelection<E>,
    delete_app_after_install: bool,
    team: Option<DeveloperTeam>,
}

impl<C: MaxCertsCallback, E: ExtensionsBehaviorCallback> Sideloader<C, E> {
    /// Construct a new `Sideloader` instance with the provided configuration
    ///
    /// See [`crate::sideload::SideloaderBuilder`] for more details and a more convenient way to construct a `Sideloader`.
    pub fn new(
        dev_session: DeveloperSession,
        apple_email: String,
        team_selection: TeamSelection,
        max_certs_behavior: MaxCertsBehavior<C>,
        machine_name: String,
        storage: Box<dyn SideloadingStorage>,
        extensions_behavior: ExtensionsBehaviorSelection<E>,
        delete_app_after_install: bool,
    ) -> Self {
        Sideloader {
            team_selection,
            storage,
            dev_session,
            machine_name,
            apple_email,
            max_certs_behavior,
            extensions_behavior,
            delete_app_after_install,
            team: None,
        }
    }

    /// Sign the app at the provided path and return the path to the signed app bundle (in a temp dir). To sign and install, see [`Self::install_app`].
    /// `pairing_file` is the optional pairing file to be encrypted and placed in the bundle if installing AltStore.
    /// `device_udid` is the optional device UDID to be used for AltStore pairing file injection.
    pub async fn sign_app<F, Fut>(
        &mut self,
        app_path: PathBuf,
        team: Option<DeveloperTeam>,
        // this will be replaced with proper entitlement handling later
        increased_memory_limit: bool,
        progress_callback: Option<F>,
        pairing_file: Option<&[u8]>,
        device_udid: Option<&str>,
    ) -> Result<(PathBuf, Option<SpecialApp>), Report>
    where
        F: Fn(f32) -> Fut,
        Fut: Future<Output = ()>,
    {
        let team = match team {
            Some(t) => t,
            None => self.get_team().await?,
        };
        let cert_identity = CertificateIdentity::retrieve(
            &self.machine_name,
            &self.apple_email,
            &mut self.dev_session,
            &team,
            self.storage.as_ref(),
            &self.max_certs_behavior,
        )
        .await
        .context("Failed to retrieve certificate identity")?;

        if let Some(callback) = &progress_callback {
            callback(0.1).await;
        }

        let mut app = Application::new(app_path)?;
        let special = app.get_special_app();

        let main_bundle_id = app.main_bundle_id()?;
        let main_app_name = app.main_app_name()?;
        let team_suffix = format!(".{}", team.team_id);
        // Don't append the team ID twice if the IPA was already patched with it
        let main_app_id_str = if main_bundle_id.ends_with(&team_suffix) {
            main_bundle_id.clone()
        } else {
            format!("{}{}", main_bundle_id, team_suffix)
        };
        app.update_bundle_id(&main_bundle_id, &main_app_id_str)?;

        let extensions_behavior = self
            .extensions_behavior
            .behavior(app.bundle.app_extensions())
            .await?;
        let mut app_ids = app
            .register_app_ids(&extensions_behavior, &mut self.dev_session, &team)
            .await?;
        let main_app_id = match app_ids
            .iter()
            .find(|app_id| app_id.identifier == main_app_id_str)
        {
            Some(id) => id,
            None => {
                bail!(
                    "Main app ID {} not found in registered app IDs",
                    main_app_id_str
                );
            }
        }
        .clone();

        let group_identifier = format!(
            "group.{}",
            if Some(SpecialApp::SideStoreLc) == special {
                format!("com.SideStore.SideStore.{}", team.team_id)
            } else {
                main_app_id_str.clone()
            }
        );

        let app_group = self
            .dev_session
            .ensure_app_group(&team, &main_app_name, &group_identifier, None)
            .await?;

        for app_id in app_ids.iter_mut() {
            app_id
                .ensure_group_feature(&mut self.dev_session, &team)
                .await?;

            self.dev_session
                .assign_app_group(&team, &app_group, app_id, None)
                .await?;

            if increased_memory_limit {
                self.dev_session
                    .add_increased_memory_limit(&team, app_id)
                    .await?;
            }
        }

        if let Some(callback) = &progress_callback {
            callback(0.15).await;
        }

        info!("App IDs configured");

        app.apply_special_app_behavior(
            &special,
            &group_identifier,
            &cert_identity,
            pairing_file,
            device_udid,
        )
        .await
        .context("Failed to modify app bundle")?;

        let main_provisioning_profile = self
            .dev_session
            .download_team_provisioning_profile(&team, &main_app_id, None)
            .await?;

        let mut provisioning_profiles: Vec<(String, Profile, Dictionary)> = Vec::new();

        match extensions_behavior {
            ExtensionsBehavior::ReuseMain => {
                // For each extension bundle id, push the main provisioning profile and entitlements to the provisioning_profiles vector
                let main_entitlements =
                    ProvisioningProfile::parse(main_provisioning_profile.encoded_profile.as_ref())?
                        .entitlements()
                        .clone();
                let extensions = app.bundle.app_extensions();
                for ext in extensions {
                    provisioning_profiles.push((
                        ext.bundle_identifier().unwrap_or_default().to_string(),
                        main_provisioning_profile.clone(),
                        main_entitlements.clone(),
                    ));
                }
            }
            ExtensionsBehavior::RegisterAll => {
                for id in app_ids
                    .into_iter()
                    .filter(|id| id.identifier != main_app_id.identifier)
                {
                    let bundle_id = id.identifier.clone();

                    let is_watch = app.bundle.app_extensions().iter().any(|e| {
                        e.is_watch_app() && e.bundle_identifier() == Some(bundle_id.as_str())
                    });

                    // Watch apps get a watchOS profile (which lists the registered watches);
                    // fall back to the default profile type if Apple refuses.
                    let watch_profile = if is_watch {
                        match self
                            .dev_session
                            .download_team_provisioning_profile(
                                &team,
                                &id,
                                crate::dev::device_type::DeveloperDeviceType::Watchos,
                            )
                            .await
                        {
                            Ok(p) => Some(p),
                            Err(e) => {
                                tracing::warn!(
                                    "watchOS profile download failed for {} ({}), using the default profile",
                                    bundle_id,
                                    e
                                );
                                None
                            }
                        }
                    } else {
                        None
                    };

                    let profile = match watch_profile {
                        Some(p) => p,
                        None => self
                            .dev_session
                            .download_team_provisioning_profile(&team, &id, None)
                            .await
                            .context(format!(
                                "Failed to download provisioning profile for {}",
                                bundle_id
                            ))?,
                    };

                    if is_watch {
                        log_profile_devices(&bundle_id, &profile);
                    }

                    let parsed_profile =
                        ProvisioningProfile::parse(profile.encoded_profile.as_ref())?;
                    let entitlements = parsed_profile.entitlements().clone();

                    provisioning_profiles.push((bundle_id, profile, entitlements));
                }
            }
        }

        if let Some(callback) = &progress_callback {
            callback(0.2).await;
        }

        info!("Acquired provisioning profile");

        app.bundle.write_info()?;
        for ext in app.bundle.app_extensions_mut() {
            ext.write_info()?;
        }
        for ext in app.bundle.frameworks_mut() {
            ext.write_info()?;
        }

        // isideload_vfs::fs::write(
        //     app.bundle.bundle_dir.join("embedded.mobileprovision"),
        //     provisioning_profile.encoded_profile.as_ref(),
        // )?;

        if let Some(callback) = &progress_callback {
            callback(0.3).await;
        }

        sign::sign(
            &mut app,
            &cert_identity,
            &main_provisioning_profile,
            &mut provisioning_profiles,
            &special,
            &team,
            progress_callback,
        )
        .await
        .context("Failed to sign app")?;

        info!("App signed!");

        Ok((app.bundle.bundle_dir.clone(), special))
    }

    #[cfg(feature = "install")]
    /// Sign and install an app to a device.
    /// This is more intended to be a helper function for simple use cases, for more complex scenarios you should call `sign_app` and `install_app` separately.
    /// `pairing_file` is the optional pairing file to be encrypted and placed in the bundle if installing AltStore.
    /// `device_udid` is the optional device UDID to be used for AltStore pairing file injection.
    pub async fn install_app<F, Fut>(
        &mut self,
        device_provider: &impl IdeviceProvider,
        app_path: PathBuf,
        // this is gross but will be replaced with proper entitlement handling later
        increased_memory_limit: bool,
        progress_callback: Option<F>,
        pairing_file: Option<&[u8]>,
    ) -> Result<Option<SpecialApp>, Report>
    where
        F: Fn(f32) -> Fut,
        Fut: Future<Output = ()>,
    {
        let device_info = IdeviceInfo::from_device(device_provider).await?;

        let team = self.get_team().await?;
        self.dev_session
            .ensure_device_registered(&team, &device_info.name, &device_info.udid, None)
            .await?;

        // Register paired Apple Watches too, so the provisioning profiles include
        // them and an embedded Watch app can actually be installed on the watch.
        let has_watch_app = Application::new(app_path.clone())
            .map(|a| a.bundle.app_extensions().iter().any(|e| e.is_watch_app()))
            .unwrap_or(false);
        if has_watch_app {
            self.register_paired_watches(device_provider, &team).await;
        }

        let (signed_app_path, special_app) = self
            .sign_app(
                app_path,
                Some(team),
                increased_memory_limit,
                progress_callback,
                pairing_file,
                Some(&device_info.udid),
            )
            .await?;

        info!("Transferring App...");

        let last_logged_progress = std::sync::Arc::new(std::sync::Mutex::new(0));
        crate::sideload::install::install_app(device_provider, &signed_app_path, |progress| {
            let mut last_progress = last_logged_progress.lock().unwrap();
            if progress >= *last_progress + 10 {
                *last_progress = progress;
                info!("Installing: {}%", progress);
            }
        })
        .await
        .context("Failed to install app on device")?;

        if self.delete_app_after_install
            && let Err(e) = isideload_vfs::fs::remove_dir_all(signed_app_path)
        {
            tracing::warn!("Failed to remove temporary signed app file: {}", e);
        }

        Ok(special_app)
    }

    #[cfg(feature = "install")]
    /// Register every Apple Watch paired with the connected iPhone as a development device.
    /// Extra UDIDs can be given with the `ISIDELOAD_WATCH_UDID` environment variable
    /// (comma separated) in case the paired watch can't be detected automatically.
    pub async fn register_paired_watches(
        &mut self,
        device_provider: &impl IdeviceProvider,
        team: &DeveloperTeam,
    ) {
        use crate::dev::device_type::DeveloperDeviceType;

        let mut watches: Vec<(String, String)> =
            match crate::util::device::paired_watches(device_provider).await {
                Ok(w) => w.into_iter().map(|w| (w.name, w.udid)).collect(),
                Err(e) => {
                    tracing::warn!("Could not list paired Apple Watches: {}", e);
                    Vec::new()
                }
            };
        if let Ok(extra) = std::env::var("ISIDELOAD_WATCH_UDID") {
            for udid in extra.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
                if !watches.iter().any(|(_, u)| u.eq_ignore_ascii_case(udid)) {
                    watches.push(("Apple Watch".to_string(), udid.to_string()));
                }
            }
        }
        if watches.is_empty() {
            tracing::warn!(
                "No paired Apple Watch found; the Watch app will probably fail to install"
            );
            return;
        }

        for (name, udid) in watches {
            info!("Registering Apple Watch {} ({})", name, udid);
            let res = self
                .dev_session
                .ensure_device_registered(team, &name, &udid, DeveloperDeviceType::Watchos)
                .await;
            if let Err(e) = res {
                tracing::warn!(
                    "watchOS registration failed ({}), retrying with the default device type",
                    e
                );
                if let Err(e) = self
                    .dev_session
                    .ensure_device_registered(team, &name, &udid, None)
                    .await
                {
                    tracing::warn!("Failed to register Apple Watch {}: {}", udid, e);
                }
            }
        }
    }

    /// Get the developer team according to the configured team selection behavior
    pub async fn get_team(&mut self) -> Result<DeveloperTeam, Report> {
        if let Some(team) = &self.team {
            return Ok(team.clone());
        }
        let teams = self.dev_session.list_teams().await?;
        let team = match teams.len() {
            0 => {
                bail!("No developer teams available")
            }
            1 => teams.into_iter().next().ok_or_report()?,
            _ => {
                info!(
                    "Multiple developer teams found, {} as per configuration",
                    self.team_selection
                );
                match &self.team_selection {
                    TeamSelection::First => teams.into_iter().next().ok_or_report()?,
                    TeamSelection::PromptOnce(prompt_fn)
                    | TeamSelection::PromptAlways(prompt_fn) => {
                        let selection =
                            prompt_fn(&teams).ok_or_else(|| report!("No team selected"))?;
                        teams
                            .into_iter()
                            .find(|t| t.team_id == selection)
                            .ok_or_else(|| report!("No team found with ID {}", selection))?
                    }
                }
            }
        };
        if !matches!(&self.team_selection, TeamSelection::PromptAlways(_)) {
            self.team = Some(team.clone());
        }
        Ok(team)
    }

    pub fn get_dev_session(&mut self) -> &mut DeveloperSession {
        &mut self.dev_session
    }

    pub fn get_email(&self) -> &str {
        &self.apple_email
    }
}

/// Log which devices a provisioning profile covers (the plist is stored in clear text inside the CMS envelope)
fn log_profile_devices(bundle_id: &str, profile: &Profile) {
    let data: &[u8] = profile.encoded_profile.as_ref();
    let text = String::from_utf8_lossy(data);
    let devices: Vec<String> = text
        .split("<key>ProvisionedDevices</key>")
        .nth(1)
        .and_then(|rest| rest.split("</array>").next())
        .map(|arr| {
            arr.split("<string>")
                .skip(1)
                .filter_map(|s| s.split("</string>").next())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default();
    info!(
        "Profile for {} covers {} device(s): {}",
        bundle_id,
        devices.len(),
        devices.join(", ")
    );
}
