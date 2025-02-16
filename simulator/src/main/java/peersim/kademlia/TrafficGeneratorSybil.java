package peersim.kademlia;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import peersim.config.Configuration;
import peersim.core.CommonState;
import peersim.core.Control;
import peersim.core.Network;
import peersim.core.Node;
import peersim.edsim.EDSimulator;

/**
 * Generates malicious Sybil traffic targeting honest nodes.
 */
public class TrafficGeneratorSybil implements Control {

    private static final String PAR_PROT = "protocol";
    private final int pid;
    private boolean first = true;

    public TrafficGeneratorSybil(String prefix) {
        pid = Configuration.getPid(prefix + "." + PAR_PROT);
    }

    private Message generateHonestPutMessage() {
        try {
            String topic = "t1";
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(topic.getBytes(StandardCharsets.UTF_8));
            BigInteger id = new BigInteger(1, hash);
            String data = "GOOD DATA HERE";
            Message m = Message.makeInitPutValue(id, data);
            m.timestamp = CommonState.getTime();
            System.out.println("Sybil PUT message sent: " + m.body);
            return m;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    private Message generateHonestGetMessage() {
        try {
            String topic = "t1";
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(topic.getBytes(StandardCharsets.UTF_8));
            BigInteger id = new BigInteger(1, hash);
            Message m = Message.makeInitGetValue(id);
            m.timestamp = CommonState.getTime();
            return m;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    public boolean execute() {
        // Select a random honest node to store data
        Node targetNode;
        do {
            targetNode = Network.get(CommonState.r.nextInt(Network.size()));
        } while (targetNode == null || ((KademliaProtocol) targetNode.getProtocol(pid)).getNode().isEvil());

        System.out
                .println("Storing data at node: " + ((KademliaProtocol) targetNode.getProtocol(pid)).getNode().getId());

        // Step 1: PUT data into the network
        EDSimulator.add(0, generateHonestPutMessage(), targetNode, pid);

        // Step 2: After some delay, attempt to GET the data
        EDSimulator.add(5000, generateHonestGetMessage(), targetNode, pid);

        return false;
    }

}
