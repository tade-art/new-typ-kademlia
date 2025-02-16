package peersim.kademlia.operations;

import java.math.BigInteger;
import java.util.HashMap;
import peersim.core.Network;
import peersim.kademlia.KademliaCommonConfig;
import peersim.kademlia.Util;

public class RegionBasedFindOperation extends FindOperation {

    public int minCPL;
    protected HashMap<BigInteger, Boolean> regionalSet;
    public BigInteger targetNode;

    /**
     * Default constructor
     *
     * @param srcNode   Id of the source node
     * @param destNode  Id of the node to find
     * @param k         Number of honest nodes
     * @param timestamp Timestamp of the operation
     */
    public RegionBasedFindOperation(BigInteger srcNode, BigInteger destNode, int k, long timestamp) {
        super(srcNode, destNode, timestamp);
        this.minCPL = (int) Math.ceil(Math.log(Network.size() / (double) k) / Math.log(2)) - 1;
        this.regionalSet = new HashMap<>();
        this.targetNode = destNode;
    }

    /**
     * Update closestSet with the new information received
     *
     * @param neighbours Array of neighbour node IDs
     */
    @Override
    public void elaborateResponse(BigInteger[] neighbours) {
        for (BigInteger neighbour : neighbours) {
            if (neighbour != null && !regionalSet.containsKey(neighbour)) {
                if (Util.prefixLen(neighbour, this.targetNode) >= this.minCPL) {
                    this.regionalSet.put(neighbour, false);
                }
            }
        }
        super.elaborateResponse(neighbours);
    }

    /**
     * Get the first neighbour in closest set which has not been already queried
     *
     * @return the Id of the node or null if there aren't available nodes
     */
    @Override
    public BigInteger getNeighbour() {
        BigInteger neighbour = super.getNeighbour();
        if (neighbour == null && available_requests == KademliaCommonConfig.ALPHA) {
            int currMinCPL = Util.getMinCplWithSet(this.targetNode, this.closestSet.keySet());
            if (currMinCPL <= this.minCPL) {
                return null;
            } else {
                updateDestinationNode(currMinCPL);
            }
        }

        if (neighbour != null && regionalSet.containsKey(neighbour)) {
            regionalSet.put(neighbour, true);
        }

        return neighbour;
    }

    /**
     * Update the destination node based on the current minimum common prefix length
     * (CPL).
     *
     * @param currMinCPL The current minimum CPL.
     */
    private void updateDestinationNode(int currMinCPL) {
        this.destNode = Util.flipBit(this.targetNode, currMinCPL);
        this.closestSet.clear();
        for (BigInteger node : regionalSet.keySet()) {
            if (closestSet.size() < KademliaCommonConfig.K) {
                closestSet.put(node, false);
            } else {
                replaceFurthestNode(node);
            }
        }
    }

    /**
     * Replace the furthest node in the closest set with a new node if the new node
     * is closer.
     *
     * @param node The new node to potentially add to the closest set.
     */
    private void replaceFurthestNode(BigInteger node) {
        BigInteger newDist = Util.xorDistance(node, destNode);
        BigInteger maxDist = newDist;
        BigInteger nodeMaxDist = node;
        for (BigInteger existingNode : closestSet.keySet()) {
            BigInteger dist = Util.xorDistance(existingNode, destNode);
            if (dist.compareTo(maxDist) > 0) {
                maxDist = dist;
                nodeMaxDist = existingNode;
            }
        }

        if (!nodeMaxDist.equals(node)) {
            closestSet.remove(nodeMaxDist);
            closestSet.put(node, false);
        }
    }
}
