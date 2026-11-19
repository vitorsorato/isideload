//! watchload: sideload an IPA that contains an Apple Watch app with a free Apple ID.
//!
//! Differences from the stock isideload/iloader flow:
//! - the embedded `Watch/*.app` gets its own app ID, provisioning profile and signature
//! - every Apple Watch paired with the connected iPhone is registered on the team
//!
//! Usage: watchload <app.ipa> [apple-id]
//! The password is read from the terminal without echo. Extra watch UDIDs can be
//! given with ISIDELOAD_WATCH_UDID=<udid>[,<udid>...].

use idevice::usbmuxd::{UsbmuxdAddr, UsbmuxdConnection};
use isideload::{
    anisette::remote_v3::RemoteV3AnisetteProvider,
    auth::apple_account::{AppleAccount, TwoFactorCallbackParams, TwoFactorCallbackResponse},
    dev::{
        certificates::DevelopmentCertificate, developer_session::DeveloperSession,
        teams::DeveloperTeam,
    },
    sideload::{SideloaderBuilder, TeamSelection, builder::MaxCertsBehavior},
    util::{callbacks::ExtensionsBehaviorCallbackBox, keyring_storage::KeyringStorage},
};
use std::{
    env,
    io::{self, Write},
    path::PathBuf,
};

use tracing::Level;
use tracing_subscriber::FmtSubscriber;

fn prompt(label: &str) -> String {
    print!("{label}");
    io::stdout().flush().ok();
    let mut s = String::new();
    io::stdin().read_line(&mut s).unwrap();
    s.trim().to_string()
}

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");
    isideload::init().expect("Failed to initialize error reporting");
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    let args: Vec<String> = env::args().collect();
    let Some(app_path) = args.get(1).map(PathBuf::from) else {
        eprintln!("Uso: watchload <app.ipa> [apple-id]");
        std::process::exit(2);
    };
    if !app_path.exists() {
        eprintln!("Arquivo não encontrado: {}", app_path.display());
        std::process::exit(2);
    }

    let apple_id = match args.get(2) {
        Some(id) => id.clone(),
        None => prompt("Apple ID (email): "),
    };
    let apple_password = rpassword::prompt_password("Senha do Apple ID (não aparece ao digitar): ")
        .expect("Failed to read password");

    let get_2fa_code = async |params: TwoFactorCallbackParams| {
        if params.unknown {
            println!("O último método de 2FA falhou, tente outro.");
        } else {
            println!(
                "Digite o código de verificação enviado para {}:",
                if params.sms {
                    params
                        .numbers
                        .iter()
                        .find(|n| Some(n.id) == params.selected_number_id)
                        .map(|n| n.number_with_dial_code.clone())
                        .unwrap_or_else(|| "seu telefone".to_string())
                } else {
                    "seus aparelhos".to_string()
                }
            );
        }

        let other_numbers: Vec<_> = params
            .numbers
            .iter()
            .filter(|n| Some(n.id) != params.selected_number_id)
            .collect();
        if params.unknown || params.sms {
            println!("Ou digite \"d\" para receber o código nos seus aparelhos.");
        }
        if !other_numbers.is_empty() {
            println!("Ou escolha outro número (digite \"p<id>\", ex.: \"p1\"):");
            for n in other_numbers.iter() {
                println!("ID {}: {}", n.id, n.number_with_dial_code);
            }
        }
        if !params.unknown {
            println!("Digite \"r\" para reenviar o código.");
        }

        let mut code = String::new();
        std::io::stdin().read_line(&mut code).unwrap();
        let code = code.trim();

        if let Some(id) = code.strip_prefix('p')
            && let Ok(id) = id.parse::<u32>()
        {
            return Ok(TwoFactorCallbackResponse::SendSms(id));
        }
        if code == "d" {
            return Ok(TwoFactorCallbackResponse::SendToDevices);
        }
        if code == "r" && !params.unknown {
            return Ok(TwoFactorCallbackResponse::ResendCode);
        }
        Ok(TwoFactorCallbackResponse::SubmitCode(code.to_string()))
    };

    let mut account = AppleAccount::builder(&apple_id)
        .anisette_provider(
            RemoteV3AnisetteProvider::default()
                .unwrap()
                .set_serial_number("2".to_string()),
        )
        .login(&apple_password, get_2fa_code)
        .await
        .unwrap_or_else(|e| panic!("Falha no login: {e}"));
    drop(apple_password);

    let dev_session = DeveloperSession::from_account(&mut account)
        .await
        .expect("Failed to create developer session");

    let mut usbmuxd = UsbmuxdConnection::default()
        .await
        .unwrap_or_else(|e| panic!("Falha ao conectar no usbmuxd: {e:?}"));
    let devs = usbmuxd.get_devices().await.unwrap();
    let Some(dev) = devs.first() else {
        panic!("Nenhum iPhone encontrado. Conecte o iPhone pelo cabo e desbloqueie.");
    };
    let provider = dev.to_provider(UsbmuxdAddr::from_env_var().unwrap(), "watchload");

    let team_selection_prompt = |teams: &Vec<DeveloperTeam>| {
        println!("Escolha o time:");
        for (index, team) in teams.iter().enumerate() {
            println!(
                "{}: {} ({})",
                index + 1,
                team.name.as_deref().unwrap_or("<Sem nome>"),
                team.team_id
            );
        }
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        let selection = input.trim().parse::<usize>().ok()?;
        if selection == 0 || selection > teams.len() {
            return None;
        }
        Some(teams[selection - 1].team_id.clone())
    };

    let cert_selection_prompt = async |certs: Vec<DevelopmentCertificate>| {
        println!("Limite de certificados atingido. Escolha quais revogar:");
        for (index, cert) in certs.iter().enumerate() {
            println!(
                "({}) {}: {}",
                index + 1,
                cert.name.as_deref().unwrap_or("<Sem nome>"),
                cert.machine_name.as_deref().unwrap_or("<Sem máquina>"),
            );
        }
        println!("Digite os números separados por vírgula:");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        let selections: Vec<usize> = input
            .trim()
            .split(',')
            .filter_map(|s| s.trim().parse::<usize>().ok())
            .filter(|&n| n > 0 && n <= certs.len())
            .collect();
        if selections.is_empty() {
            return Ok(None);
        }
        Ok(Some(
            selections
                .into_iter()
                .map(|n| certs[n - 1].serial_number.clone().unwrap_or_default())
                .collect::<Vec<_>>(),
        ))
    };

    let mut sideloader =
        SideloaderBuilder::<_, ExtensionsBehaviorCallbackBox>::new(dev_session, apple_id.clone())
            .team_selection(TeamSelection::PromptOnce(team_selection_prompt))
            .max_certs_behavior(MaxCertsBehavior::Prompt(cert_selection_prompt))
            .storage(Box::new(KeyringStorage::new("watchload".to_string())))
            .machine_name("watchload".to_string())
            .delete_app_after_install(std::env::var("WATCHLOAD_KEEP").is_err())
            .build();

    let result = sideloader
        .install_app(
            &provider,
            app_path,
            false,
            None::<fn(f32) -> std::future::Ready<()>>,
            None,
        )
        .await;
    match result {
        Ok(_) => {
            println!();
            println!("App instalado no iPhone!");
            println!("Agora abra o app Watch no iPhone > Meu Relógio > Apps Disponíveis e toque em Instalar.");
            if std::env::var("WATCHLOAD_KEEP").is_ok() {
                println!(
                    "App assinado guardado em: {}",
                    std::env::temp_dir().display()
                );
            }
        }
        Err(e) => {
            eprintln!("Erro: {e}");
            std::process::exit(1);
        }
    }
}
