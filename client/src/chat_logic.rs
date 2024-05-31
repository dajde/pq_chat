use crate::*;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    Aes256Gcm, Key, Nonce,
};
use base64::{self, Engine};
use chrono;
use crossterm::{
    terminal::{disable_raw_mode, LeaveAlternateScreen},
    ExecutableCommand,
};
use lib::{messages::*, sql::*, *};
use log::{error, info, warn};
use oqs::{kem, sig};
use std::{
    fs::{File, OpenOptions},
    io::{stdin, stdout, Error, ErrorKind, Read, Write},
    path::Path,
    process::exit,
    sync::mpsc::Sender,
    time::Duration,
};
use tokio::net::{
    tcp::{OwnedReadHalf, OwnedWriteHalf},
    TcpStream,
};
use uuid::Uuid;

/// Initialize the userdata file containing the username and the user's base64 encoded private DSA key
pub fn init_userdata(username: String, key: &sig::SecretKey) -> Result<()> {
    let encoded_key: String = base64::engine::general_purpose::STANDARD.encode(key.as_ref());

    let userdata = UserData {
        username,
        priv_dsa: encoded_key,
    };

    let json_string = match serde_json::to_string_pretty(&userdata) {
        Ok(s) => s,
        Err(_) => return log_and_err!("Failed to serialize userdata"),
    };

    let mut file = match File::create("userdata.json") {
        Ok(file) => file,
        Err(_) => return log_and_err!("Failed to create userdata file"),
    };

    match file.write_all(json_string.as_bytes()) {
        Ok(_) => {}
        Err(_) => return log_and_err!("Failed to write to userdata file"),
    }

    Ok(())
}

/// Read the userdata file containing the username and the user's base64 encoded private DSA key
pub fn read_userdata(mut file: File) -> Result<(String, sig::SecretKey)> {
    info!("Reading userdata file");

    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let userdata: UserData = serde_json::from_str(&contents)?;

    let key_bytes =
        match base64::engine::general_purpose::STANDARD.decode(userdata.priv_dsa.as_bytes()) {
            Ok(key) => key,
            Err(_) => return log_and_err!("Failed to decode private key"),
        };

    let dsa = sig::Sig::new(sig::Algorithm::Dilithium5).expect("Failed to create DSA");
    let key = dsa
        .secret_key_from_bytes(&key_bytes)
        .expect("Failed to parse private key")
        .to_owned();

    info!("Userdata file read successfully");
    Ok((userdata.username, key))
}

/// Read the ks_pub file containing key server's base64 encoded public DSA key
fn read_ks_pub(mut file: File) -> Result<sig::PublicKey> {
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let key_bytes = match base64::engine::general_purpose::STANDARD.decode(contents) {
        Ok(key) => key,
        Err(_) => return log_and_err!("Failed to decode public key of key server"),
    };

    let dsa = sig::Sig::new(sig::Algorithm::Dilithium5)?;
    let key = match dsa.public_key_from_bytes(&key_bytes) {
        Some(key) => key.to_owned(),
        None => return log_and_err!("Failed to parse public key of key server"),
    };

    Ok(key)
}

/// Initialize the user's store.db SQLite database.
/// Contains the tables for the session keys, contacts, contact requests, private KEM keys and KEM bundles
pub fn init_store() -> Result<()> {
    create_session_key_table()?;
    create_contacts_table()?;
    create_contact_requests_table()?;
    create_privkem_table()?;
    create_kem_bundles_table_user()?;

    Ok(())
}

/// Read or create app config file
pub fn read_or_create_config(file_path: &str) -> Result<AppConfig> {
    let path = Path::new(file_path);

    // Check if config file exists
    if !path.exists() {
        // If it doesn't exist, create it with default values
        println!("Config file not found. Creating new config file.");

        let mut keyserver_name: String = String::new();
        println!("Enter the key server address:");
        stdin().read_line(&mut keyserver_name)?;

        let mut server_name: String = String::new();
        println!("Enter the server address:");
        stdin().read_line(&mut server_name)?;

        let default_config = AppConfig {
            keyserver_name: keyserver_name.trim().to_string(),
            server_name: server_name.trim().to_string(),
            kem_lifetime: 60 * 60 * 24 * 7,     // 1 week
            session_key_lifetime: 60 * 60 * 24, // 1 day
            kem_grace_period: 60 * 60 * 6,      // 6 hours
            session_key_grace_period: 60 * 60,  // 1 hour
        };

        save_config(&default_config, file_path)?;
    }

    // Read config file
    let mut file = OpenOptions::new().read(true).open(file_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    // Deserialize config from JSON
    let config: AppConfig = serde_json::from_str(&contents)?;

    Ok(config)
}

/// Saves app config
pub fn save_config(config: &AppConfig, file_path: &str) -> Result<()> {
    let json_string = serde_json::to_string_pretty(config)?;

    let mut file = File::create(file_path)?;
    file.write_all(json_string.as_bytes())?;

    Ok(())
}

/// Register a new user
pub async fn register_user(config: &AppConfig) -> Result<(String, sig::SecretKey)> {
    let mut username: String = String::new();
    println!("Enter your username:");
    stdin().read_line(&mut username)?;
    username = username.trim().to_string();

    // Step 1 of the registration protocol - create long-term DSA keypair
    let dsa = sig::Sig::new(sig::Algorithm::Dilithium5).expect("Failed to create DSA");
    let (pk, sk) = dsa.keypair().expect("Failed to create keypair");

    // Register the user on the key server
    keyserver_register(
        &username,
        &pk.as_ref().to_vec(),
        &sk.as_ref().to_vec(),
        config,
    )
    .await?;

    Ok((username.trim().to_string(), sk))
}

/// Register the new user on the key server with the username and public DSA key
async fn keyserver_register(
    username: &String,
    pub_dsa: &Vec<u8>,
    priv_dsa: &Vec<u8>,
    config: &AppConfig,
) -> Result<()> {
    let key_server_stream = match tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect(&config.keyserver_name),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            exit_app!("Could not connect to the server. {e}. Exiting...");
        }
        Err(_) => {
            exit_app!("Connection to the server timed out. Exiting...");
        }
    };

    let (mut reader, mut writer) = key_server_stream.into_split();

    let file = match File::open("ks_pub") {
        Ok(file) => file,
        Err(_) => exit_app!(
            "Failed to open ks_pub (keyserver's public key) file. You have to create it first."
        ),
    };

    let pub_dsa_keyserver = match read_ks_pub(file) {
        Ok(key) => key,
        Err(e) => exit_app!("Failed to read key server's public key. {}", e),
    };

    let dsa = sig::Sig::new(sig::Algorithm::Dilithium5).expect("Failed to create DSA");

    // Step 2 of the registration protocol - sign the username and public DSA key.
    // Then, send the signed message to the key server.
    let to_sign = joined_vec!(username.as_bytes(), pub_dsa);
    let sk = dsa
        .secret_key_from_bytes(priv_dsa)
        .expect("Failed to parse secret key");

    let signature = dsa.sign(&to_sign, sk)?;

    let register_request = RegisterRequest {
        username: username.clone(),
        signature: signature.into_vec(),
        pub_dsa: pub_dsa.clone(),
    };

    let request = Message::RegisterRequest(register_request);

    lib::send_msg(&mut writer, &request).await?;

    // Step 5 of the registration protocol - receive the response from the key server.
    // Then, verify the key server's signature on Alice's data.
    let message: Message = receive_msg(&mut reader).await?;

    let register_response: RegisterResponse = match message {
        Message::RegisterResponse(m) => {
            info!("User registered successfully");
            m
        }
        Message::ErrorResponse(e) => exit_app!("Failed to register user. {}", e.error.message),
        _ => return log_and_err!("Unknown response"),
    };

    let signature = dsa
        .signature_from_bytes(&register_response.signature)
        .expect("Failed to parse signature");

    let to_verify = joined_vec!(username.as_bytes(), pub_dsa);

    match dsa.verify(&to_verify, &signature, &pub_dsa_keyserver) {
        Ok(_) => Ok(()),
        Err(_) => exit_app!(
            "Failed to register user. Key server signature not verified. Check ks_pub file."
        ),
    }
}

/// Get KEM bundle, either from local storage or from the key server
async fn get_kem_bundle(
    owner: &String,
    recipient: &String,
    config: &AppConfig,
    priv_dsa: &sig::SecretKey,
) -> Result<(kem::PublicKey, Vec<u8>)> {
    let dsa = sig::Sig::new(sig::Algorithm::Dilithium5).expect("Failed to create DSA");

    loop {
        // Try to get KEM bundle from local storage
        match sql::get_single_kem_bundle_by_owner(owner) {
            // If KEM bundle is found, verify timestamp and signature
            Ok(kem_bundle) => match verify_kem_bundle(
                kem_bundle.pub_kem,
                owner,
                recipient,
                kem_bundle.validity,
                &kem_bundle.uuid,
                &kem_bundle.signature,
                config,
            )
            .await
            {
                // If OK, delete KEM bundle and return it
                Ok(pk) => {
                    sql::delete_kem_bundle_user_by_uuid(&kem_bundle.uuid)?;
                    return Ok((pk, kem_bundle.uuid));
                }
                // If not OK, delete KEM bundle and try another one
                Err(e) => {
                    warn!("KEM bundle not verified. Trying another KEM bundle. {}", e);
                    sql::delete_kem_bundle_user_by_uuid(&kem_bundle.uuid)?;
                    continue;
                }
            },
            // If there is no KEM bundle in local storage, get it from the key server
            Err(_) => {
                // Construct KEM bundle request signature
                let current_time = chrono::Utc::now().timestamp();

                let to_sign = joined_vec!(
                    owner.as_bytes(),
                    recipient.as_bytes(),
                    current_time.to_be_bytes()
                );

                let signature = dsa
                    .sign(&to_sign, priv_dsa)
                    .expect("Failed to sign KEM bundle request");

                // Send KEM bundle request to the key server and receive response
                let bundles_response: Message;
                {
                    let key_server_stream = match tokio::time::timeout(
                        Duration::from_secs(5),
                        TcpStream::connect(&config.keyserver_name),
                    )
                    .await
                    {
                        Ok(Ok(stream)) => stream,
                        Ok(Err(e)) => {
                            exit_app!("Could not connect to the server. {e}. Exiting...");
                        }
                        Err(_) => {
                            exit_app!("Connection to the server timed out. Exiting...");
                        }
                    };

                    let (mut reader, mut writer) = key_server_stream.into_split();

                    let kem_bundle_request = KemBundleRequest {
                        owner: owner.clone(),
                        recipient: recipient.clone(),
                        signature: signature.into_vec(),
                        timestamp: current_time,
                    };

                    let request = Message::KemBundleRequest(kem_bundle_request);

                    lib::send_msg(&mut writer, &request).await?;

                    bundles_response = receive_msg(&mut reader).await?;
                }

                let mut kem_bundles = match bundles_response {
                    Message::KemBundles(kem_bundles) => kem_bundles,
                    _ => return log_and_err!("Received wrong message kind"),
                };

                // Verify one KEM bundle for returning, store the rest
                let (pub_kem, uuid): (kem::PublicKey, Vec<u8>);
                loop {
                    // If we did not receive anything, we have to wait for the other user to publish a new KEM bundle
                    if kem_bundles.data.is_empty() {
                        return log_and_err!(
                            "No KEM bundles available. The other user has to publish a new KEM bundle."
                        );
                    }

                    // Verify one KEM bundle for immediate use
                    let kem_bundle: KemBundle =
                        kem_bundles.data.pop().expect("Failed to get pKEM bundle");
                    match verify_kem_bundle(
                        kem_bundle.pub_kem.clone(),
                        &kem_bundle.owner,
                        &kem_bundle.recipient,
                        kem_bundle.validity,
                        &kem_bundle.uuid,
                        &kem_bundle.signature,
                        config,
                    )
                    .await
                    {
                        Ok(pk) => {
                            pub_kem = pk;
                            uuid = kem_bundle.uuid;
                            info!("KEM bundle verified");
                            break;
                        }
                        Err(e) => {
                            warn!("KEM bundle not verified. Trying another KEM bundle. {}", e);
                            continue;
                        }
                    }
                }

                // Store the rest of the KEM bundles for later use
                for kem_bundle in kem_bundles.data.iter() {
                    match sql::store_kem_bundle_user(
                        &kem_bundle.owner,
                        &kem_bundle.pub_kem,
                        &kem_bundle.signature,
                        kem_bundle.validity,
                        &kem_bundle.uuid,
                    ) {
                        Ok(_) => info!("KEM bundle stored"),
                        Err(e) => error!("Failed to store KEM bundle. {}", e),
                    }
                }

                return Ok((pub_kem, uuid));
            }
        };
    }
}

/// Step 7 of the key establishment protocol - verify the KEM bundle.
/// Verify the owner's signature on the KEM bundle and check the validity timestamp.
async fn verify_kem_bundle(
    pub_kem: Vec<u8>,
    owner: &String,
    recipient: &String,
    validity: i64,
    uuid: &Vec<u8>,
    signature: &Vec<u8>,
    config: &AppConfig,
) -> Result<kem::PublicKey> {
    let dsa = sig::Sig::new(sig::Algorithm::Dilithium5).expect("Failed to create DSA");

    let signature = dsa
        .signature_from_bytes(signature)
        .expect("Failed to parse signature");

    let to_verify = joined_vec!(
        &pub_kem,
        owner.as_bytes(),
        recipient.as_bytes(),
        validity.to_be_bytes(),
        uuid
    );

    let pub_dsa = get_pubdsa(owner, config).await?;

    // Verify owner's signature on KEM bundle
    match dsa.verify(&to_verify, &signature, &pub_dsa) {
        Ok(_) => info!("Owner's signature on KEM bundle verified"),
        Err(_) => return log_and_err!("Owner's signature on KEM bundle not verified"),
    }

    // Verify KEM bundle validity
    let current_time = chrono::Utc::now().timestamp();
    if validity < current_time {
        return log_and_err!("KEM bundle expired");
    }

    let kem = kem::Kem::new(kem::Algorithm::Kyber1024).expect("Failed to create KEM");

    let pk_kem = kem
        .public_key_from_bytes(pub_kem.as_slice())
        .expect("Failed to parse public key");

    Ok(pk_kem.to_owned())
}

// Get the public DSA key from the key server
async fn get_pubdsa(username: &String, config: &AppConfig) -> Result<sig::PublicKey> {
    let stream = match tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect(&config.keyserver_name),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            exit_app!("Could not connect to the server. {e}. Exiting...");
        }
        Err(_) => {
            exit_app!("Connection to the server timed out. Exiting...");
        }
    };

    let (mut tcpreader, mut tcpwriter) = stream.into_split();

    let request = PubDsaRequest {
        username: username.clone(),
    };

    let request = Message::PubDsaRequest(request);

    lib::send_msg(&mut tcpwriter, &request)
        .await
        .expect("Failed to send public key request");

    let message: Message = receive_msg(&mut tcpreader).await?;

    let message = match message {
        Message::PubDsa(pub_dsa) => pub_dsa,
        _ => return log_and_err!("Received wrong message kind"),
    };

    //Verify key server's signature
    let dsa = sig::Sig::new(sig::Algorithm::Dilithium5).expect("Failed to create DSA");

    let pub_dsa_keyserver = read_ks_pub(File::open("ks_pub")?)?;

    let signature = dsa
        .signature_from_bytes(&message.signature)
        .expect("Failed to parse signature");
    let to_verify = joined_vec!(message.username.as_bytes(), &message.pub_dsa);

    match dsa.verify(&to_verify, &signature, &pub_dsa_keyserver) {
        Ok(_) => info!("Key server's PUB_DSA signature verified"),
        Err(_) => {
            return log_and_err!("Key server's PUB_DSA signature not verified. Message dropped.");
        }
    }

    let pk = dsa
        .public_key_from_bytes(&message.pub_dsa as &[u8])
        .expect("Failed to parse public key");

    Ok(pk.to_owned())
}

/// Publish a new KEM bundle to the key server, storing the private KEM key locally
pub async fn publish_kem_bundle(
    owner: &String,
    recipient: &String,
    priv_dsa: &sig::SecretKey,
    config: &AppConfig,
) -> Result<()> {
    let key_server_stream = match tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect(&config.keyserver_name),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            exit_app!("Could not connect to the server. {e}. Exiting...");
        }
        Err(_) => {
            exit_app!("Connection to the server timed out. Exiting...");
        }
    };

    let (_reader, mut writer) = key_server_stream.into_split();

    let dsa = sig::Sig::new(sig::Algorithm::Dilithium5).expect("Failed to create DSA");

    // Step 1 of the key establishment protocol - create a new short term KEM keypair
    let kemalg = kem::Kem::new(kem::Algorithm::Kyber1024).expect("Failed to create KEM");
    let (pk, sk) = kemalg.keypair().expect("Failed to create KEM keypair");

    // Generate timestamp for KEM bundle validity
    let validity = chrono::Utc::now().timestamp() + config.kem_lifetime;

    // Generate UUID for KEM bundle
    let id = Uuid::new_v4();
    let id = id.as_bytes();

    // Step 2 of the key establishment protocol - send the signed KEM bundle to the key server
    // KEM bundle consists of the public KEM key, the owner's username, the recipient's username, the validity timestamp and the UUID
    let to_sign = joined_vec!(
        pk.as_ref(),
        owner.as_bytes(),
        recipient.as_bytes(),
        validity.to_be_bytes(),
        id
    );

    let signature = dsa
        .sign(&to_sign, priv_dsa)
        .expect("Failed to sign KEM bundle");

    store_privkem(&recipient, sk.as_ref(), validity, id)?;

    let kem_bundle = KemBundle {
        owner: owner.clone(),
        recipient: recipient.clone(),
        pub_kem: pk.as_ref().to_vec(),
        signature: signature.into_vec(),
        validity,
        uuid: id.to_vec(),
    };

    let message = Message::KemBundle(kem_bundle);

    lib::send_msg(&mut writer, &message).await?;
    Ok(())
}

/// Send a contact request to the recipient
pub async fn send_contact_request(model: &Model, writer: &mut OwnedWriteHalf) {
    // Publish 10 KEM bundles for the new contact
    for _ in 0..10 {
        publish_kem_bundle(
            &model.username,
            &model.input,
            &model.priv_dsa,
            &model.config,
        )
        .await
        .expect("Failed to publish KEM bundle");
    }

    // Send contact request to the recipient
    let contact_request = ContactRequest {
        from: model.username.clone(),
        to: model.input.clone(),
    };

    let message = Message::ContactRequest(contact_request);

    lib::send_msg(writer, &message)
        .await
        .expect("Failed to send contact request");

    store_contact(model.input.as_str()).expect("Failed to store contact");
}

/// Accept a contact request and publish KEM bundles to the key server
pub async fn accept_contact_request(model: &Model) {
    if model.list_selected >= model.contact_requests.len() {
        return;
    }

    let contact = model.contact_requests[model.list_selected].clone();

    // Publish 10 KEM bundles for the new contact
    for _ in 0..10 {
        publish_kem_bundle(&model.username, &contact, &model.priv_dsa, &model.config)
            .await
            .expect("Failed to publish KEM bundle");
    }

    store_contact(contact.as_str()).expect("Failed to store contact");
    remove_contact_request(contact.as_str()).expect("Failed to remove contact request");
}

/// Decline a contact request
pub fn decline_contact_request(model: &Model) {
    if model.list_selected >= model.contact_requests.len() {
        return;
    }

    let contact = model.contact_requests[model.list_selected].clone();
    remove_contact_request(contact.as_str()).expect("Failed to remove contact request");
}

/// Send encrypted message to the recipient
pub async fn send_message(model: &Model, writer: &mut OwnedWriteHalf) -> Result<()> {
    let current_time = chrono::Utc::now().timestamp();

    let (mut shared_key, key_validity) = get_latest_session_key(model.recipient.as_str())?;

    // If the sender does not share a session key with the recipient or the session key is expired, create a new session key
    if shared_key.is_empty() || key_validity < current_time {
        info!(
            "No valid session key for {} found. Creating new session key",
            model.recipient
        );
        // Step 4 of the key establishment protocol - get Bob's KEM bundle
        let (pk_kem, uuid) = match get_kem_bundle(
            &model.recipient,
            &model.username,
            &model.config,
            &model.priv_dsa,
        )
        .await
        {
            Ok(pk) => pk,
            Err(e) => return log_and_err!("Failed to obtain a KEM bundle. {}", e),
        };

        // Step 8 of the key establishment protocol - encapsulate Bob's public KEM key
        let kem = kem::Kem::new(kem::Algorithm::Kyber1024).expect("Failed to create KEM");
        let (ct, ss) = kem
            .encapsulate(&pk_kem)
            .expect("Failed to encapsulate PUB_KEM");
        shared_key = ss.into_vec();

        let timestamp = current_time + model.config.session_key_lifetime;

        store_session_key(model.recipient.as_str(), shared_key.as_ref(), timestamp)?;

        // Step 9 of the key establishment protocol - send the signed KEM ciphertext to Bob together with the UUID and the session key validity timestamp
        let to_sign = joined_vec!(
            ct.as_ref(),
            model.recipient.as_bytes(),
            model.username.as_bytes(),
            timestamp.to_be_bytes(),
            &uuid
        );

        let dsa = sig::Sig::new(sig::Algorithm::Dilithium5).expect("Failed to create DSA");
        let signature = dsa
            .sign(&to_sign, &model.priv_dsa)
            .expect("Failed to sign message");
        let signature = signature.into_vec();

        let ct_msg = KemCipherText {
            from: model.username.clone(),
            to: model.recipient.clone(),
            ciphertext: ct.into_vec(),
            signature,
            sk_validity: timestamp,
            uuid,
        };

        let ct_msg = Message::KemCipherText(ct_msg);

        lib::send_msg(writer, &ct_msg).await?;
    }

    // Create payload for encryption containing the message and it's metadata
    let metadata = joined_vec!(
        model.username.as_bytes(),
        model.recipient.as_bytes(),
        current_time.to_be_bytes()
    );

    let payload = Payload {
        msg: model.input.as_bytes(),
        aad: metadata.as_slice(),
    };

    // Encrypt message with the shared session key
    let key = Key::<Aes256Gcm>::from_slice(shared_key.as_ref());
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, payload)
        .expect("Failed to encrypt message");

    let message = TextMessage {
        from: model.username.clone(),
        to: model.recipient.clone(),
        content: ciphertext,
        nonce: nonce.to_vec(),
        sent_timestamp: current_time,
    };

    let message = Message::TextMessage(message);

    lib::send_msg(writer, &message).await?;
    Ok(())
}

/// Receives messages from the server
pub async fn message_receiver(
    reader: &mut OwnedReadHalf,
    priv_dsa: &sig::SecretKey,
    tx: Sender<TextMessage>,
    config: &AppConfig,
) {
    loop {
        match receive_msg(reader).await {
            Ok(m) => match handle_message(m, &tx, config, priv_dsa).await {
                Ok(_) => {}
                Err(e) => error!("Failed to handle message. {}", e),
            },
            Err(e) => {
                error!("Failed to receive message. {}", e);
                return;
            }
        }
    }
}

/// Handle received messages.
/// Decrypt and display text messages.
/// Verify and decapsulate KEM ciphertexts, store session keys and publish new KEM bundles.
/// Store contact requests.
pub async fn handle_message(
    message: Message,
    tx: &Sender<TextMessage>,
    config: &AppConfig,
    priv_dsa: &sig::SecretKey,
) -> Result<()> {
    match message {
        Message::TextMessage(message) => {
            info!("Received MESSAGE");
            // Try to decrypt message with each of the saved session keys
            let session_keys = match get_all_session_keys_by_recipient(&message.from) {
                Ok(keys) => keys,
                Err(_) => {
                    return log_and_err!("Failed to get session keys. Dropping message");
                }
            };
            let nonce = Nonce::from_slice(&message.nonce);

            for (secret_key, key_validity) in session_keys.iter() {
                // Only try valid keys
                if message.sent_timestamp <= (key_validity + config.session_key_grace_period) {
                    let key = Key::<Aes256Gcm>::from_slice(secret_key);
                    let cipher = Aes256Gcm::new(&key);

                    // Add message to payload together with authenticated metadata
                    let metadata = joined_vec!(
                        message.from.as_bytes(),
                        message.to.as_bytes(),
                        message.sent_timestamp.to_be_bytes()
                    );

                    let payload = Payload {
                        msg: message.content.as_slice(),
                        aad: metadata.as_slice(),
                    };

                    // Try to decrypt message
                    let plaintext = match cipher.decrypt(nonce, payload) {
                        Ok(plaintext) => plaintext,
                        Err(_) => {
                            error!("Failed to decrypt message. Trying another session key or dropping message");
                            continue;
                        }
                    };

                    // Send message to TUI if successful
                    let message = TextMessage {
                        from: message.from,
                        to: message.to,
                        content: plaintext,
                        sent_timestamp: message.sent_timestamp,
                        nonce: message.nonce,
                    };

                    match tx.send(message) {
                        Ok(_) => {
                            info!("Message sent to TUI");
                            return Ok(());
                        }
                        Err(e) => {
                            return log_and_err!("Failed to send message to TUI. {}", e);
                        }
                    }
                }
            }

            error!("Failed to decrypt message. Dropping message");
            return Ok(());
        }
        Message::KemCipherText(message) => {
            info!("Received KEM_CT");
            // Steps 10-13 of the key establishment protocol - verify the signatures, validity and decapsulate the KEM ciphertext.
            // Store the session key and publish a new KEM bundle.
            // Delete the old private KEM key.
            let pub_dsa_rec: sig::PublicKey = match get_pubdsa(&message.from, config).await {
                Ok(pub_dsa) => pub_dsa,
                Err(e) => {
                    return log_and_err!(
                        "Failed to get PUB_DSA of CT_KEM sender. Message dropped. {}",
                        e
                    );
                }
            };

            let dsa = match sig::Sig::new(sig::Algorithm::Dilithium5) {
                Ok(dsa) => dsa,
                Err(_) => {
                    return log_and_err!("Failed to create DSA. Message dropped");
                }
            };

            let signature = match dsa.signature_from_bytes(&message.signature) {
                Some(signature) => signature,
                None => {
                    return log_and_err!("Failed to parse signature. Message dropped");
                }
            };

            let to_verify: Vec<u8> = joined_vec!(
                &message.ciphertext,
                message.to.as_bytes(),
                message.from.as_bytes(),
                message.sk_validity.to_be_bytes(),
                &message.uuid
            );

            match dsa.verify(&to_verify, &signature, &pub_dsa_rec) {
                Ok(_) => info!("Sender's CT_KEM signature verified"),
                Err(_) => {
                    return log_and_err!("Sender's CT_KEM signature not verified. Message dropped");
                }
            }

            // Decapsulate KEM ciphertext
            let kem = match kem::Kem::new(kem::Algorithm::Kyber1024) {
                Ok(kem) => kem,
                Err(_) => {
                    return log_and_err!("Failed to create KEM. Message dropped");
                }
            };

            let ct = match kem.ciphertext_from_bytes(&message.ciphertext) {
                Some(ct) => ct,
                None => {
                    return log_and_err!("Failed to parse CT_KEM. Message dropped");
                }
            };

            let (priv_kem, validity, is_replaced) =
                match get_privkem_by_uuid(message.uuid.as_slice()) {
                    Ok((priv_kem, timestamp, is_replaced)) => (priv_kem, timestamp, is_replaced),
                    Err(_) => {
                        return log_and_err!("Failed to get PRIV_KEM. Message dropped");
                    }
                };

            if chrono::Utc::now().timestamp() >= validity + config.kem_grace_period {
                return log_and_err!("PRIV_KEM expired. Message dropped");
            }

            let priv_kem = match kem.secret_key_from_bytes(&priv_kem) {
                Some(priv_kem) => priv_kem,
                None => {
                    return log_and_err!("Failed to parse PRIV_KEM. Message dropped");
                }
            };

            let ss = match kem.decapsulate(&priv_kem, &ct) {
                Ok(ss) => ss,
                Err(_) => {
                    return log_and_err!("Failed to decapsulate PRIV_KEM. Message dropped");
                }
            };

            let key = Key::<Aes256Gcm>::from_slice(ss.as_ref());

            // Store session key for later use and publish new KEM bundle
            if let Err(_) = store_session_key(&message.from, key.as_ref(), message.sk_validity) {
                error!("Failed to store session key");
            }

            // Publish new KEM bundle if private KEM key is not replaced yet by the clean up routine
            if !is_replaced {
                match publish_kem_bundle(&message.to, &message.from, priv_dsa, config).await {
                    Ok(_) => {}
                    Err(_) => {
                        return log_and_err!("Failed to publish KEM bundle. Message dropped");
                    }
                }
            }

            // Delete old private KEM key for forward secrecy
            match delete_privkem(&message.uuid) {
                Ok(_) => {}
                Err(_) => return log_and_err!("Failed to delete PRIV_KEM"),
            }

            return Ok(());
        }
        Message::ContactRequest(message) => match store_contact_request(&message.from) {
            Ok(_) => Ok(()),
            Err(_) => return log_and_err!("Failed to store contact request"),
        },
        _ => {
            warn!("Received unknown message kind");
            Ok(())
        }
    }
}

/// Join the server and receive stored messages
/// Returns the writer and reader halves of the TcpStream
pub async fn join_server(
    username: &String,
    tx: &Sender<TextMessage>,
    config: &AppConfig,
    priv_dsa: &sig::SecretKey,
) -> Result<(OwnedWriteHalf, OwnedReadHalf)> {
    let stream = match tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect(&config.server_name),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            exit_app!("Could not connect to the server. {e}. Exiting...");
        }
        Err(_) => {
            exit_app!("Connection to the server timed out. Exiting...");
        }
    };

    // Set TCP keepalive, so the connection is not dropped
    let sock_ref = socket2::SockRef::from(&stream);

    let mut keep_alive = socket2::TcpKeepalive::new();
    keep_alive = keep_alive.with_time(Duration::from_secs(20));
    keep_alive = keep_alive.with_interval(Duration::from_secs(20));

    sock_ref.set_tcp_keepalive(&keep_alive)?;

    let (mut reader, mut writer) = stream.into_split();

    // Send stored messages request
    let request = Message::ServerGreeting(ServerGreeting {
        username: username.clone(),
    });

    lib::send_msg(&mut writer, &request)
        .await
        .expect("Failed to send server greeting request");

    // Receive stored messages
    let response = receive_msg(&mut reader)
        .await
        .expect("Failed to receive stored messages");

    let messages = match response {
        Message::StoredMessagesResponse(messages) => messages,
        _ => {
            return log_and_err!("Received wrong message kind");
        }
    };

    // Handle stored messages
    for message in messages.messages.into_iter() {
        match handle_message(message, tx, config, priv_dsa).await {
            Ok(_) => {}
            Err(e) => {
                error!("Failed to handle stored message. {}", e);
            }
        }
    }

    // Start expired key cleanup thread
    let username = username.clone();
    let priv_dsa = priv_dsa.clone();
    let config = config.clone();

    tokio::spawn(async move { clean_up(&username, &priv_dsa, &config).await });

    Ok((writer, reader))
}

/// Clean up expired session keys and private KEM keys
pub async fn clean_up(owner: &String, priv_dsa: &sig::SecretKey, config: &AppConfig) {
    loop {
        let current_time = chrono::Utc::now().timestamp();
        info!("Starting clean up. Current time {}", current_time);

        // Iterate over all session keys and delete expired ones
        let sessions_keys = get_all_session_keys().expect("Failed to get session keys");
        for (id, _, _, validity) in sessions_keys.iter() {
            if current_time > (*validity + config.session_key_grace_period) {
                delete_session_key(*id).expect("Failed to delete session key");
            }
        }

        // Iterate over all private KEM keys and delete expired ones.
        let priv_kems = get_all_privkem().expect("Failed to get privkem");
        for (id, recipient, _, validity, is_replaced) in priv_kems.iter() {
            // Publish new KEM bundle if private KEM key is expired and not replaced yet
            if (current_time > *validity) && !is_replaced {
                match publish_kem_bundle(owner, recipient, priv_dsa, config).await {
                    Ok(_) => {
                        info!("Published new KEM bundle for {}", recipient);
                        set_replaced_privkem(id).expect("Failed to set replaced flag for PRIV_KEM");
                    }
                    Err(e) => {
                        error!("Failed to publish KEM bundle for {}. {}", recipient, e);
                    }
                }
            }

            // Delete old private KEM key for forward secrecy.
            // This is done after the grace period, so delayed messages can still be decapsulated.
            if current_time > (*validity + config.kem_grace_period) {
                info!("Deleting privkem with validity {}", *validity);
                delete_privkem(id).expect("Failed to delete privkem");
            }
        }

        info!("Expired key cleanup done");
        // Run cleanup every 10 minutes
        tokio::time::sleep(Duration::from_secs(600)).await;
    }
}
