package peersim.kademlia;

import java.math.BigInteger;
import peersim.config.Configuration;
import peersim.core.CommonState;
import peersim.core.Network;
import peersim.core.Node;

/**
 * This class introduces Sybil nodes into the network by creating multiple nodes
 * with the same attacker ID.
 */
public class MaliciousCustomDistribution implements peersim.core.Control {

    private static final String PAR_PROT = "protocol";
    private static final String PAR_SYBIL_COUNT = "sybil.count";

    private int protocolID;
    private int sybilCount;
    private UniformRandomGenerator urg;

    public MaliciousCustomDistribution(String prefix) {
        protocolID = Configuration.getPid(prefix + "." + PAR_PROT);
        sybilCount = Configuration.getInt(prefix + "." + PAR_SYBIL_COUNT);
        urg = new UniformRandomGenerator(KademliaCommonConfig.BITS, CommonState.r);
        System.out.println("Sybil count: " + sybilCount);
    }

    public boolean execute() {
        int totalSybilNodes = 0;

        for (int i = 0; i < Network.size(); ++i) {
            Node generalNode = Network.get(i);
            BigInteger id = urg.generate();
            KademliaNode node = null;

            if (Math.random() < 0.7) {
                node = new KademliaNode(id, "0.0.0.0", 0); // Honest node
            } else {
                // Ensure we select a valid victim node
                KademliaNode victim = null;
                Node victimNode = null;

                for (int attempts = 0; attempts < Network.size(); attempts++) {
                    victimNode = Network.get(CommonState.r.nextInt(Network.size()));
                    if (victimNode != null && victimNode.getProtocol(protocolID) instanceof KademliaProtocol) {
                        victim = ((KademliaProtocol) victimNode.getProtocol(protocolID)).getNode();
                        if (victim != null) {
                            break; // Found a valid victim node
                        }
                    }
                }

                if (victim == null) {
                    System.err.println("Error: Could not find a valid victim node.");
                    return false; // Stop execution if no valid victim found
                }

                // System.out.println("Victim selected: ID = " + victim.getId());

                // Generate Sybil nodes with attacker's ID
                BigInteger attackerID = victim.getId();
                for (int j = 0; j < sybilCount; j++) {
                    BigInteger sybilNodeID = urg.generate(); // Unique ID for each Sybil node
                    node = new KademliaNode(sybilNodeID, attackerID, "0.0.0.0", 0);
                    ((KademliaProtocol) (generalNode.getProtocol(protocolID))).setNode(node);
                    totalSybilNodes++;
                }
            }

            KademliaProtocol kadProt = ((KademliaProtocol) (generalNode.getProtocol(protocolID)));
            generalNode.setKademliaProtocol(kadProt);
            kadProt.setNode(node);
            kadProt.setProtocolID(protocolID);
        }

        System.out.println("Total Sybil nodes created: " + totalSybilNodes);
        return false;
    }
}
