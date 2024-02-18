# AdaptiveNet

A custom network layer protocol, with variable length addresses implemented on SDN using ONOS and P4.

"https://github.com/opennetworkinglab/ngsdn-tutorial" NGSDN Tutorial by ONF was referenced a lot for developing this project. Some of the starter code and project structure is borrowed from there. This repo is actually a detached fork of NGSDN Tutorial.

The following are dependencies:

* Docker v1.13.0+ (with docker-compose)
* make
* Python 3
* Bash-like Unix shell
* Wireshark (optional)



## Get this repo or pull latest changes

To work on the exercises you will need to clone this repo:

    git pull origin vla_dev


## commands (borrowed from ngsdn repo)

To build and debug the system we provide a set of make-based commands
to control the different aspects of the system:

| Make command        | Description                                            |
|---------------------|------------------------------------------------------- |
| `make deps`         | Pull and build all required dependencies               |
| `make p4-build`     | Build P4 program                                       |
| `make p4-test`      | Run PTF tests                                          |
| `make start`        | Start Mininet and ONOS containers                      |
| `make stop`         | Stop all containers                                    |
| `make restart`      | Restart containers clearing any previous state         |
| `make onos-cli`     | Access the ONOS CLI (password: `rocks`, Ctrl-D to exit)|
| `make onos-log`     | Show the ONOS log                                      |
| `make mn-cli`       | Access the Mininet CLI (Ctrl-D to exit)                |
| `make mn-log`       | Show the Mininet log (i.e., the CLI output)            |
| `make app-build`    | Build custom ONOS app                                  |
| `make app-reload`   | Install and activate the ONOS app                      |
| `make netcfg`       | Push netcfg.json file (network config) to ONOS         |


