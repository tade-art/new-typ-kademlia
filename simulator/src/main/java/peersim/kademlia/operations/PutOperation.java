package peersim.kademlia.operations;

import java.math.BigInteger;

/**
 * This class represents a find operation and offer the methods needed to
 * maintain and update the
 * closest set.<br>
 * It also maintains the number of parallel requsts that can has a maximum of
 * ALPHA.
 *
 * @author Daniele Furlan, Maurizio Bonani
 * @version 1.0
 */
public class PutOperation extends FindOperation {

  Object value;

  /**
   * defaul constructor
   *
   * @param destNode Id of the node to find
   */
  public PutOperation(BigInteger srcNode, BigInteger value, long timestamp) {
    super(srcNode, value, timestamp);
  }

  /**
   * Save found value in get operation
   *
   * @param value
   */
  public void setValue(Object value) {
    this.value = value;
  }

  /** Get found value in get operation */
  public Object getValue() {
    return value;
  }
}
