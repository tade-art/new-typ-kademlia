package peersim.kademlia;

import java.math.BigInteger;
import java.util.HashSet;
import java.util.Set;

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
    private static int totalSybilNodesCreated = 0;
    private static KademliaNode firstHonestNode = null;
    public static BigInteger firstHonestNodeID = null;
    public static final Set<BigInteger> knownMaliciousNodes = new HashSet<>();

    public MaliciousCustomDistribution(String prefix) {
        protocolID = Configuration.getPid(prefix + "." + PAR_PROT);
        sybilCount = Configuration.getInt(prefix + "." + PAR_SYBIL_COUNT);
        urg = new UniformRandomGenerator(KademliaCommonConfig.BITS, CommonState.r);
    }

    public boolean execute() {
        for (int i = 0; i < Network.size(); ++i) {
            Node generalNode = Network.get(i);
            BigInteger id = urg.generate();
            KademliaNode node = null;

            if (firstHonestNode == null) {
                firstHonestNodeID = id;
                firstHonestNode = new KademliaNode(id, "0.0.0.0", 0);
                node = firstHonestNode;
                System.out.println("First honest node created with ID: " + id);
            }

            else if (totalSybilNodesCreated < sybilCount) {
                BigInteger attackerID = firstHonestNode.getId();
                BigInteger sybilNodeID = urg.generate(); // Unique ID for Sybil node
                node = new KademliaNode(sybilNodeID, attackerID, "0.0.0.0", 0);
                knownMaliciousNodes.add(sybilNodeID);
                // System.out.println("Generated Sybil node with ID: " + sybilNodeID);
                totalSybilNodesCreated++;
            }

            else {
                node = new KademliaNode(id, "0.0.0.0", 0);
            }

            KademliaProtocol kadProt = ((KademliaProtocol) (generalNode.getProtocol(protocolID)));
            generalNode.setKademliaProtocol(kadProt);
            kadProt.setNode(node);
            kadProt.setProtocolID(protocolID);
        }
        return false;
    }
}
