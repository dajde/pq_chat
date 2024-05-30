# pq_chat

A simple TUI chat application that uses post-quantum cryptography for secure communication.

## Build

Before building the project, you need to have `rust` and `cargo` installed on your system. You can install them by following the instructions on the [Rust website](https://www.rust-lang.org/tools/install).

Other development dependencies are `libclang-dev`, `cmake`, `libssl-dev`, `build-essential`, `git` and `curl`. You can install them on `apt` based systems by running the following command:

```bash
$ apt install build-essential git curl libclang-dev cmake libssl-dev
```

In the root directory of the project, run the following command:

```bash
$ make
```

This builds the client, server and keyserver. The built binaries are linked statically and are located in the `bin` directory.

You can also build the project regularly using `cargo`:

```bash
$ cargo build
```

## Download

You can download the built binaries for x86_64 Linux from the [releases page](https://github.com/dajde/pq_chat/releases).

## Running the chat application

### Server

To run the server, simply run the following command:

```bash
$ ./server
```

This command will start the server on the default port 3000. It will also create the database file `data.db` in the working directory and starts logging to the file `log` and to the console.

> **_NOTE:_** The `data.db` file gets created each time you restart the server.

### Keyserver

When running the keyserver for the first time, you need to initialize the keyserver with the `--init` option. This will create the database file `keys.db` in the working directory.

It will also create the files `ks_pub` and `ks_priv` in the working directory. These files contain the public and private keys of the keyserver.

> **_IMPORTANT:_** You have to **copy** the `ks_pub` file to the client working directory and name it `kskey` before running the client.

```bash
$ ./keyserver --init
```

After initializing the keyserver, you can run it normally:

```bash
$ ./keyserver
```

To reinitialize the `keys.db` file (to delete registered users and published KEM bundles), you can use the `--reset` option:

```bash
$ ./keyserver --reset
```

### Client

To run the client, you need to copy the `ks_pub` file from the keyserver working directory to the client working directory and name it `kskey`.

Then you can run the client:

```bash
$ ./client
```

The client will prompt you to enter the key server and server IP addresses and ports. Then it will ask you to enter your username.

### Using cargo

You can also run the client, server and keyserver using `cargo`:

```bash
$ cargo run --bin server
$ cargo run --bin keyserver
$ cargo run --bin client
```
