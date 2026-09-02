```text
 ___         _        _ _      _   _
|_ _|_ _  __| |_ __ _| | |__ _| |_(_)___ _ _
 | || ' \(_-<  _/ _` | | / _` |  _| / _ \ ' \
|___|_||_/__/\__\__,_|_|_\__,_|\__|_\___/_||_|

```

## Boltconn installation

There are two options available for installing boltconn on your system, (1) a prebuilt binary and
(2) manually building the application from source.

### Installing a prebuilt binary

Prebuilt binary images can be downloaded on the [latest
release](https://github.com/XOR-op/BoltConn/releases/latest) page of the boltconn repository. 

### Building and installing boltconn from source

While it is preferred to install a prebuilt binary, there are those instances when a manual build is
preferred. 

### 0. Satisfy dependencies

BoltConn is programmed in the rust programming language, so before you can build it yourself, you
must have a working copy of the rust programming language on your system which with many systems
will be accompanied by Cargo, the rust packaging management system. 

#### Installing rust

If you do not have rust yet installed on your system, you have two rather simple methods to achieve
it’s installation. You can either download it from the package repository of your distribution or
you can use the "rustup.rs" tool to perform a userland installation. 

For using the package manager of your linux distribution, normally this is a matter of running:
```bash
sudo apt install rust
# OR
sudo dnf install rust
```

For acquiring rust through rustup simply run the following in your terminal:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# and then
rustup install
```
Which should provide you with a working installation of rust on your system. Then ensure that the
executables for rust are located in your path.


### 1. Acquire a copy of the source code

First, you will need to get a copy of the source code. To do so you must already have git installed
on your system, from there you will run:

```bash
git clone https://github.com/XOR-op/BoltConn && cd BoltConn
```

This will create a new folder on your system labeled "BoltConn" and will have changed directory into the repository folder.

### 2. Download required libraries and build the package

Downloading the required libraries for boltconn and performing the build operation can be performed
in one simple command. 

```bash
cargo build .
```

### 3. Install Boltconn

Once BoltConn has been built, you will then need to install it in your system.

```bash
sudo cargo install .
```

### 4. Finishing up

To ensure that you have successfully installed boltconn on your system run the following command:

```bash
boltconn -v
```

