# Kademlia Simulator

## Overview
 
This is a Kademlia Simulator that was used in the research project for the new Service Discovery in Ethereum 2.0 (Discv5) (available at: https://github.com/datahop/p2p-service-discovery). The simulator is built on top of [PeerSim](http://peersim.sourceforge.net/) and it is based on the Kademlia implementation from Daniele Furlan and Maurizio Bonani that can be found [here](http://peersim.sourceforge.net/code/kademlia.zip).

## Requirements

To run the simulator it is necessary to have Java and Maven installed. For Ubuntu systems just run:

```shell
$ sudo apt install maven default-jdk
```

## How to run it

To execute a simulation it is necessary to call the run.sh, with a configuration file as a parameter. This has to be done within the 'kademlia-simulator/simulator' directory. For example:

```shell
$ cd kademlia-simulator/simulator
$ ./run.sh config/kademlia.cfg
```

## How to create your own scenario file

Follow PeerSim [documentation](http://peersim.sourceforge.net/tutorialed/)

## Code Documentation

The Kademlia Simulator is structured into several key files and directories, each serving a specific purpose. Each file should contain javadoc comments to help digest the codebase. Some important files to consider / review are:

### 1. `src/main/java/peersim/kademlia/KademliaProtocol.java`
   - Defines the Kademlia protocol logic, including message processing and attack detection and mitigation.
   - Implements node lookup and content storage functionalities.

### 2. `src/main/java/peersim/kademlia/operations/*`
   - This is a directory which contains the code for all operations used within the kademlia simulator
   - Contains: Find, Get, Put and RegionBasedFind

### 3. `src/main/java/peersim/kademlia/MaliciousCustomDistribution.java`
   - Java file which contains the initalisation of the sybil attack
   - Used within configs when building a network to initialise a malicious attack against a chosen node

### 4. `simulator/config/*`
   - Directory which contains the different config files that are used for running the simulator.
   - Each file contains different input fields which can be used to customize the simulation to a specific criteria

For additional details on extending or modifying the simulator, refer to the PeerSim documentation.

## How to edit config files

To edit a config file, you have to understand how the config files are read and which values to change

Using 'config/kademlia_putget.cfg' as an example, these fields can be edited to change the output of the simulation
```shell
init.1uniqueNodeID peersim.kademlia.MaliciousCustomDistribution
init.1uniqueNodeID.protocol 3kademlia
init.1uniqueNodeID.sybil.count 16
```
- kademlia.* - This is the file used to initalise the distribution of nodes, currently there are only two files to be selected from
- sybil.count - This field is used to initalise the amount of sybil nodes that are placed within the network, can be changed to add in more or less nodes

```shell
#TrafficGenerator class sends and initial 
control.0traffic peersim.kademlia.TrafficGeneratorPutGet
```
- This parameter initalises the traffic that is generated on the network itself, there are more files to view within the kademlia

```shell
# control.2turbolenceAdd peersim.kademlia.Turbulence
# control.2turbolenceAdd.protocol 3kademlia
# control.2turbolenceAdd.transport 2unreltr
# control.2turbolenceAdd.step TURBULENCE_STEP
# control.2turbolenceAdd.p_idle 0.5
# control.2turbolenceAdd.p_rem 0.25
# control.2turbolenceAdd.p_add 0.25
```
- These parameters are currently commented out in all config files however if uncommented, these parameters can simulate churn and can drop nodes from the network

To run these config files, refer to the previous section titled "How to run it"

## How to create a protocol on top of Kademlia

TBC
