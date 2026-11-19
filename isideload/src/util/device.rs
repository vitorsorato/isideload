use idevice::{IdeviceService, lockdown::LockdownClient, provider::IdeviceProvider};
use rootcause::prelude::*;

pub struct IdeviceInfo {
    pub name: String,
    pub udid: String,
}

impl IdeviceInfo {
    pub fn new(name: String, udid: String) -> Self {
        Self { name, udid }
    }

    pub async fn from_device(device: &impl IdeviceProvider) -> Result<Self, Report> {
        let mut lockdown = LockdownClient::connect(device)
            .await
            .context("Failed to connect to device lockdown")?;
        let pairing = device
            .get_pairing_file()
            .await
            .context("Failed to get device pairing file")?;
        lockdown
            .start_session(&pairing)
            .await
            .context("Failed to start lockdown session")?;
        let device_name = lockdown
            .get_value(Some("DeviceName"), None)
            .await
            .context("Failed to get device name")?
            .as_string()
            .ok_or_else(|| report!("Device name is not a string"))?
            .to_string();

        let device_udid = lockdown
            .get_value(Some("UniqueDeviceID"), None)
            .await
            .context("Failed to get device UDID")?
            .as_string()
            .ok_or_else(|| report!("Device UDID is not a string"))?
            .to_string();

        Ok(Self::new(device_name, device_udid))
    }
}

/// An Apple Watch paired with the connected iPhone
pub struct PairedWatch {
    pub name: String,
    pub udid: String,
}

/// List the Apple Watches paired with the connected iPhone, using the
/// `com.apple.companion_proxy` service (the same one Xcode uses).
pub async fn paired_watches(device: &impl IdeviceProvider) -> Result<Vec<PairedWatch>, Report> {
    use idevice::companion_proxy::CompanionProxy;

    let mut proxy = CompanionProxy::connect(device)
        .await
        .context("Failed to connect to companion_proxy")?;
    let udids = proxy
        .get_device_registry()
        .await
        .context("Failed to list paired Apple Watches")?;

    let mut watches = Vec::new();
    for udid in udids {
        let name = match proxy.get_value(udid.clone(), "DeviceName").await {
            Ok(v) => v.as_string().map(|s| s.to_string()),
            Err(_) => None,
        }
        .unwrap_or_else(|| "Apple Watch".to_string());
        watches.push(PairedWatch { name, udid });
    }
    Ok(watches)
}

/// Install provisioning profiles on the device's system profile store (misagent),
/// like Xcode does. AppConduit looks up the Apple Watch app's profile there and
/// pushes it to the watch before installing the watch app.
pub async fn install_profiles(
    device: &impl IdeviceProvider,
    profiles: Vec<(String, Vec<u8>)>,
) -> Result<(), Report> {
    use idevice::misagent::MisagentClient;

    let mut client = MisagentClient::connect(device)
        .await
        .context("Failed to connect to misagent")?;
    for (name, data) in profiles {
        match client.install(data).await {
            Ok(()) => tracing::info!("Installed provisioning profile on device: {}", name),
            Err(e) => tracing::warn!("Failed to install provisioning profile {}: {}", name, e),
        }
    }
    Ok(())
}
