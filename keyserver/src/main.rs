use base64::{self, Engine};
use lib::{errors::ServerError, messages::*, sql::*, *};
use log::{error, info};
use oqs::sig::{self, SecretKey};
use simplelog::*;
use sqlite::Connection;
use std::{
    env,
    fs::File,
    io::{Error, ErrorKind, Read, Write},
    sync::Arc,
    vec,
};
use tokio::sync::Mutex;

async fn get_pubdsa(
    mut stream: tokio::net::tcp::OwnedWriteHalf,
    message: PubDsaRequest,
    thread_connection: Arc<Mutex<Connection>>,
) -> Result<()> {
    let (public_key, sig);

    {
        let conn = thread_connection.lock().await;

        (public_key, sig) = lib::sql::get_pubdsa(&conn, &message.username.trim())?;
    }

    let response = PubDsa {
        username: message.username,
        pub_dsa: public_key,
        signature: sig,
    };

    let response = Message::PubDsa(response);

    send_msg(&mut stream, &response).await?;
    Ok(())
}

async fn register_user(
    stream: &mut tokio::net::tcp::OwnedWriteHalf,
    message: RegisterRequest,
    thread_connection: Arc<Mutex<Connection>>,
    ks_priv: &SecretKey,
) -> std::result::Result<(), ServerError> {
    let dsa = sig::Sig::new(sig::Algorithm::Dilithium5)?;

    let to_verify = joined_vec!(message.username.as_bytes(), &message.pub_dsa);

    let pub_dsa = dsa
        .public_key_from_bytes(&message.pub_dsa)
        .ok_or_else(|| ServerError::unknown("Failed to construct OQS Public key"))?;
    let sig = dsa
        .signature_from_bytes(&message.signature)
        .ok_or_else(|| ServerError::unknown("Failed to construct OQS Signature"))?;

    dsa.verify(&to_verify, sig, pub_dsa)
        .map_err(|_| ServerError::invalid_signature("Failed to verify signature"))?;

    let to_sign = joined_vec!(message.username.as_bytes(), message.pub_dsa.clone());

    let signature = dsa
        .sign(&to_sign, ks_priv)
        .map_err(|_| ServerError::unknown("Failed to sign message"))?
        .into_vec();

    {
        let conn = thread_connection.lock().await;
        store_pubdsa(
            &conn,
            &message.username as &str,
            &message.pub_dsa,
            signature.as_slice(),
        )
        .map_err(|_| ServerError::username_taken(&format!("Username already taken")))?;
    }

    let response = Message::RegisterResponse(RegisterResponse { signature });

    send_msg(stream, &response).await?;
    Ok(())
}

async fn store_kem_bundle(
    message: KemBundle,
    thread_connection: Arc<Mutex<Connection>>,
) -> Result<()> {
    let public_key;

    {
        let conn = thread_connection.lock().await;

        (public_key, _) = lib::sql::get_pubdsa(&conn, &message.owner)?;
    }

    let dsa = sig::Sig::new(sig::Algorithm::Dilithium5)?;

    let to_verify = joined_vec!(
        &message.pub_kem,
        message.owner.as_bytes(),
        message.recipient.as_bytes(),
        message.validity.to_be_bytes(),
        &message.uuid
    );

    let pk = dsa
        .public_key_from_bytes(&public_key)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "Failed to parse public key"))?;

    let signature = dsa
        .signature_from_bytes(&message.signature)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "Failed to parse signature"))?;

    dsa.verify(&to_verify, &signature, pk).map_err(|e| {
        Error::new(
            ErrorKind::InvalidData,
            format!("Failed to verify signature. {}", e),
        )
    })?;

    {
        let conn = thread_connection.lock().await;

        sql::store_kem_bundle(
            &conn,
            &message.owner,
            &message.recipient,
            &message.pub_kem,
            &message.signature,
            message.validity,
            &message.uuid,
        )?;
    }

    Ok(())
}

async fn get_kem_bundles(
    mut stream: tokio::net::tcp::OwnedWriteHalf,
    message: KemBundleRequest,
    thread_connection: Arc<Mutex<Connection>>,
) -> std::result::Result<(), ServerError> {
    let conn = thread_connection.lock().await;

    let (pub_dsa_recipient, _) = sql::get_pubdsa(&conn, &message.recipient)?;
    let dsa = sig::Sig::new(sig::Algorithm::Dilithium5)?;
    let to_verify = joined_vec!(
        message.owner.as_bytes(),
        message.recipient.as_bytes(),
        message.timestamp.to_be_bytes()
    );

    let pk = dsa
        .public_key_from_bytes(&pub_dsa_recipient)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "Failed to parse public key"))?;

    let signature = dsa
        .signature_from_bytes(&message.signature)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "Failed to parse signature"))?;

    dsa.verify(&to_verify, &signature, pk).map_err(|e| {
        Error::new(
            ErrorKind::InvalidData,
            format!("Failed to verify signature. {}", e),
        )
    })?;

    let current_time = chrono::Utc::now().timestamp();

    if message.timestamp < current_time - 1 * 60 * 15 || message.timestamp > current_time + 60 {
        return Err(ServerError::timestamp_failure(
            "Timestamp is not within the last 15 minutes",
        ));
    }

    let kem_bundles = sql::get_kem_bundles(&conn, &message.owner, &message.recipient)?;

    let response = Message::KemBundles(kem_bundles);

    send_msg(&mut stream, &response).await?;
    Ok(())
}

async fn handle_connection(
    stream: tokio::net::TcpStream,
    task_connection: Arc<Mutex<Connection>>,
    ks_priv: SecretKey,
) {
    let message: Message;

    let (mut tcpreader, mut tcpwriter) = stream.into_split();

    match receive_msg(&mut tcpreader).await {
        Ok(m) => {
            message = m;
        }
        Err(_) => {
            info!("keyserver: Failed to receive request. Terminating connection");
            return;
        }
    }

    info!("keyserver: Received request type: {}", message.kind());

    match message {
        Message::KemBundle(kem_bundle) => match store_kem_bundle(kem_bundle, task_connection).await
        {
            Ok(_) => {
                info!("keyserver: Stored KEM bundle");
            }
            Err(e) => {
                error!("keyserver: Failed to store KEM bundle. {}", e);
            }
        },
        Message::KemBundleRequest(req) => {
            match get_kem_bundles(tcpwriter, req, task_connection).await {
                Ok(_) => {
                    info!("keyserver: Sent KEM bundle");
                }
                Err(e) => {
                    error!("keyserver: Failed to handle KEM bundle request. {}", e);
                }
            }
        }
        Message::RegisterRequest(req) => {
            match register_user(&mut tcpwriter, req, task_connection, &ks_priv).await {
                Ok(_) => {
                    info!("keyserver: Registered user");
                }
                Err(e) => {
                    error!("keyserver: Failed to handle register request. {}", e);
                    let response: ErrorResponse = ErrorResponse { error: e };

                    send_msg(&mut tcpwriter, &Message::ErrorResponse(response))
                        .await
                        .expect("Failed to send message");
                }
            }
        }
        Message::PubDsaRequest(req) => match get_pubdsa(tcpwriter, req, task_connection).await {
            Ok(_) => {
                info!("keyserver: Sent DSA public key");
            }
            Err(e) => {
                error!("keyserver: Failed to handle public DSA key request. {}", e);
            }
        },
        _ => {
            error!("keyserver: Invalid request");
        }
    }
    info!("keyserver: Client has disconnected");
}

fn init_keyserver_dsa() -> Result<()> {
    let dsa = sig::Sig::new(sig::Algorithm::Dilithium5).unwrap();
    let (pk, sk) = dsa.keypair().unwrap();

    let encoded_pk: String = base64::engine::general_purpose::STANDARD.encode(pk.as_ref());
    let encoded_sk: String = base64::engine::general_purpose::STANDARD.encode(sk.as_ref());

    let mut file: std::fs::File = std::fs::File::create("ks_pub")?;
    file.write_all(encoded_pk.as_bytes())?;

    let mut file: std::fs::File = std::fs::File::create("ks_priv")?;
    file.write_all(encoded_sk.as_bytes())?;

    Ok(())
}

fn read_keyserver_data(mut file: File) -> Result<sig::SecretKey> {
    let mut contents: String = String::new();
    file.read_to_string(&mut contents)
        .expect("keyserver: Failed to read keyserver data");

    let key_bytes = base64::engine::general_purpose::STANDARD.decode(contents.as_bytes())?;

    let dsa = sig::Sig::new(sig::Algorithm::Dilithium5)?;
    let key = match dsa.secret_key_from_bytes(&key_bytes) {
        Some(key) => key.to_owned(),
        None => {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "keyserver: Failed to parse private key",
            )))
        }
    };

    Ok(key)
}

#[tokio::main]
async fn main() {
    oqs::init();
    CombinedLogger::init(vec![
        TermLogger::new(
            LevelFilter::Info,
            Config::default(),
            TerminalMode::Mixed,
            ColorChoice::Auto,
        ),
        WriteLogger::new(
            LevelFilter::Info,
            Config::default(),
            File::create("log").unwrap(),
        ),
    ])
    .unwrap();

    let args: Vec<String> = env::args().collect();
    if args.len() == 2 {
        match args[1].as_str() {
            "--init" => {
                info!("keyserver: Creating tables");
                create_pubdsa_table().expect("keyserver: Failed to create keys table");
                create_kem_bundle_table().expect("keyserver: Failed to create KEM bundles table");
                init_keyserver_dsa().expect("keyserver: Failed to write keyserver data");
            }
            "--reset" => {
                info!("keyserver: Dropping public key tables");
                create_kem_bundle_table().expect("keyserver: Failed to drop KEM bundles table");
                create_pubdsa_table().expect("keyserver: Failed to drop dsa table");
            }
            _ => {
                error!("keyserver: Invalid argument");
            }
        }
    }

    let ks_priv =
        read_keyserver_data(File::open("ks_priv").expect("Failed to open public key file"))
            .expect("Failed to read private key");

    let listener = tokio::net::TcpListener::bind("0.0.0.0:4000").await.unwrap();

    info!(
        "keyserver: Server started on {}",
        listener.local_addr().unwrap()
    );

    let connection: Connection =
        Connection::open("keys.db").expect("Failed to connect to the database");

    let shared_connection = Arc::new(Mutex::new(connection));

    loop {
        let (stream, _) = listener.accept().await.unwrap();

        let task_connection = Arc::clone(&shared_connection);
        let ks_priv_clone = ks_priv.clone();

        tokio::spawn(async move {
            handle_connection(stream, task_connection, ks_priv_clone).await;
        });
    }
}
