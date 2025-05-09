package peersim.kademlia;

import java.math.BigInteger;
import peersim.config.Configuration;
import peersim.core.CommonState;
import peersim.core.Control;
import peersim.core.Network;
import peersim.core.Node;
import peersim.edsim.EDSimulator;

/**
 * This control generates random search traffic from nodes to random destination
 * node.
 *
 * @author Daniele Furlan, Maurizio Bonani
 * @version 1.0
 */

// ______________________________________________________________________________________________
public class TrafficGenerator implements Control {

  // ______________________________________________________________________________________________
  /** MSPastry Protocol to act */
  private static final String PAR_PROT = "protocol";

  /** MSPastry Protocol ID to act */
  protected final int pid;

  private boolean first = true;

  // ______________________________________________________________________________________________
  public TrafficGenerator(String prefix) {
    pid = Configuration.getPid(prefix + "." + PAR_PROT);
  }

  // ______________________________________________________________________________________________
  /**
   * generates a random find node message, by selecting randomly the destination.
   *
   * @return Message
   */
  private Message generateFindNodeMessage() {
    // existing active destination node
    Node n = Network.get(CommonState.r.nextInt(Network.size()));
    while (!n.isUp()) {
      n = Network.get(CommonState.r.nextInt(Network.size()));
    }
    BigInteger dst = ((KademliaProtocol) (n.getProtocol(pid))).getNode().getId();

    Message m = Message.makeInitFindNode(dst);
    m.timestamp = CommonState.getTime();

    return m;
  }

  // ______________________________________________________________________________________________

  /**
   * generates a random region-based find node message, by selecting randomly the
   * destination.
   *
   * @return Message
   */
  private Message generateRegionBasedFindNodeMessage() {
    // existing active destination node
    // System.out.println("Inside generateRegionBasedFindNodeMessage");
    UniformRandomGenerator urg = new UniformRandomGenerator(KademliaCommonConfig.BITS, CommonState.r);
    BigInteger id = urg.generate();
    int numHonest = 16;
    Message m = Message.makeInitRegionBasedFindNode(id, numHonest);
    m.timestamp = CommonState.getTime();
    return m;
  }

  // ______________________________________________________________________________________________
  /**
   * every call of this control generates and send a random find node message
   *
   * @return boolean
   */
  public boolean execute() {

    Node start;
    do {
      start = Network.get(CommonState.r.nextInt(Network.size()));
    } while ((start == null) || (!start.isUp()));

    // send message
    EDSimulator.add(0, generateFindNodeMessage(), start, pid);
    // EDSimulator.add(0, generateRegionBasedFindNodeMessage(), start, pid);
    // System.out.println("generated a node");

    return false;
  }

  // ______________________________________________________________________________________________

} // End of class
// ______________________________________________________________________________________________
