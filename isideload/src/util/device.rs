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
