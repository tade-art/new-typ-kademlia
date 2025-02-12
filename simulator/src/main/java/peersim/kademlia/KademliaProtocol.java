package peersim.kademlia;

/**
 * A Kademlia implementation for PeerSim extending the EDProtocol class.<br>
 * See the Kademlia bibliografy for more information about the protocol.
 *
 * @author Daniele Furlan, Maurizio Bonani
 * @version 1.0
 */
import java.math.BigInteger;
import java.util.Arrays;
// logging
import java.util.LinkedHashMap;
import java.util.TreeMap;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import peersim.config.Configuration;
import peersim.core.CommonState;
import peersim.core.Network;
import peersim.core.Node;
import peersim.edsim.EDProtocol;
import peersim.edsim.EDSimulator;
import peersim.kademlia.operations.FindOperation;
import peersim.kademlia.operations.GetOperation;
import peersim.kademlia.operations.PutOperation;
import peersim.kademlia.operations.RegionBasedFindOperation;
import peersim.transport.UnreliableTransport;

// __________________________________________________________________________________________________
public class KademliaProtocol implements EDProtocol {

  // VARIABLE PARAMETERS
  final String PAR_K = "K";
  final String PAR_ALPHA = "ALPHA";
  final String PAR_BITS = "BITS";
  final String PAR_FINDMODE = "FINDMODE";

  private static final String PAR_TRANSPORT = "transport";
  private static String prefix = null;
  private UnreliableTransport transport;
  private int tid;
  private int kademliaid;

  /** allow to call the service initializer only once */
  private static boolean _ALREADY_INSTALLED = false;

  /** routing table of this pastry node */
  private RoutingTable routingTable;

  /** trace message sent for timeout purpose */
  private TreeMap<Long, Long> sentMsg;

  /** find operations set */
  private LinkedHashMap<Long, FindOperation> findOp;

  /** Kademlia node instance */
  public KademliaNode node;

  /** logging handler */
  protected Logger logger;

  private KeyValueStore kv;

  /**
   * Replicate this object by returning an identical copy.<br>
   * It is called by the initializer and do not fill any particular field.
   *
   * @return Object
   */
  public Object clone() {
    KademliaProtocol dolly = new KademliaProtocol(KademliaProtocol.prefix);
    return dolly;
  }

  /**
   * Used only by the initializer when creating the prototype. Every other
   * instance call CLONE to
   * create the new object.
   *
   * @param prefix String
   */
  public KademliaProtocol(String prefix) {
    this.node = null; // empty nodeId
    KademliaProtocol.prefix = prefix;

    _init();

    routingTable = new RoutingTable(
        KademliaCommonConfig.NBUCKETS,
        KademliaCommonConfig.K,
        KademliaCommonConfig.MAXREPLACEMENT);

    sentMsg = new TreeMap<Long, Long>();

    findOp = new LinkedHashMap<Long, FindOperation>();

    tid = Configuration.getPid(prefix + "." + PAR_TRANSPORT);

    kv = new KeyValueStore();
  }

  /**
   * This procedure is called only once and allow to inizialize the internal state
   * of
   * KademliaProtocol. Every node shares the same configuration, so it is
   * sufficient to call this
   * routine once.
   */
  private void _init() {
    // execute once
    if (_ALREADY_INSTALLED)
      return;

    // read paramaters
    KademliaCommonConfig.K = Configuration.getInt(prefix + "." + PAR_K, KademliaCommonConfig.K);
    KademliaCommonConfig.ALPHA = Configuration.getInt(prefix + "." + PAR_ALPHA, KademliaCommonConfig.ALPHA);
    KademliaCommonConfig.BITS = Configuration.getInt(prefix + "." + PAR_BITS, KademliaCommonConfig.BITS);

    KademliaCommonConfig.FINDMODE = Configuration.getInt(prefix + "." + PAR_FINDMODE, KademliaCommonConfig.FINDMODE);

    _ALREADY_INSTALLED = true;
  }

  /**
   * Search through the network the Node having a specific node Id, by performing
   * binary serach (we
   * concern about the ordering of the network).
   *
   * @param searchNodeId BigInteger
   * @return Node
   */
  private Node nodeIdtoNode(BigInteger searchNodeId) {
    if (searchNodeId == null)
      return null;

    int inf = 0;
    int sup = Network.size() - 1;
    int m;

    while (inf <= sup) {
      m = (inf + sup) / 2;

      BigInteger mId = ((KademliaProtocol) Network.get(m).getProtocol(kademliaid)).getNode().getId();

      if (mId.equals(searchNodeId))
        return Network.get(m);

      if (mId.compareTo(searchNodeId) < 0)
        inf = m + 1;
      else
        sup = m - 1;
    }

    // perform a traditional search for more reliability (maybe the network is not
    // ordered)
    BigInteger mId;
    for (int i = Network.size() - 1; i >= 0; i--) {
      mId = ((KademliaProtocol) Network.get(i).getProtocol(kademliaid)).getNode().getId();
      if (mId.equals(searchNodeId))
        return Network.get(i);
    }

    return null;
  }

  /**
   * Perform the required operation upon receiving a message in response to a
   * ROUTE message.<br>
   * Update the find operation record with the closest set of neighbour received.
   * Than, send as many
   * ROUTE request I can (according to the ALPHA parameter).<br>
   * If no closest neighbour available and no outstanding messages stop the find
   * operation.
   *
   * @param m     Message
   * @param myPid the sender Pid
   */

  /*
   * BUG ENCOUTNERED
   * Before function is ran, the RESPONSE message is removed from the sent message
   * and FOP is removed somewhere - not found that yet since print statements
   * aren't being ran when config file is ran
   * 
   * When a response type message comes into the func, it will locate the correct
   * fop and then go through the logic to generate GET messages
   * 
   * When generating GET messages, the response message comes back into the
   * function (from handleGet) containing the value from the GET func and gets
   * flagged as complete since value has been retrieved
   * 
   * Because of this, no new messages are created or sent and since findOp list is
   * empty, the config file just hangs and never finishes - stuck in a loop
   * 
   * Potential areas where the bug is being caused - handlePut and handleGet
   * May be worth looking into handle the "else{}" logic for (if !fop.isFinished)
   * 
   * Changed implementation of PUT and GET classes and handleResponse needs to be
   * refactored to accompany this
   */

  private void handleResponse(Message m, int myPid) {
    // add message source to my routing table
    if (m.src != null)
      routingTable.addNeighbour(m.src.getId());

    // get corresponding find operation (using the message field operationId)
    FindOperation fop = this.findOp.get(m.operationId);

    // Debugging print statements
    System.out.println("Existing operation IDs: " + findOp.keySet());
    System.out.println("Current FOP being handled at top of func: " + fop.getClass().getSimpleName());

    if (fop != null) {
      fop.elaborateResponse((BigInteger[]) m.body);
      logger.info("Handleresponse FindOperation " + fop.getId() + " " + fop.getAvailableRequests());

      // save received neighbour in the closest Set of fin operation
      BigInteger[] neighbours = (BigInteger[]) m.body;
      for (BigInteger neighbour : neighbours)
        routingTable.addNeighbour(neighbour);

      if (!fop.isFinished() && Arrays.asList(neighbours).contains(fop.getDestNode())) {
        logger.warning("Found node " + fop.getDestNode());
        KademliaObserver.find_ok.add(1);
        fop.setFinished(true);
      }

      if (fop instanceof GetOperation && m.value != null) {
        fop.setFinished(true);
        ((GetOperation) fop).setValue(m.value);
        logger.warning("Getprocess finished found " + ((GetOperation) fop).getValue() + " hops " + fop.getHops());
      }

      while (fop.getAvailableRequests() > 0) { // I can send a new find request
        // get an available neighbour
        BigInteger neighbour = fop.getNeighbour();

        if (neighbour != null) {
          if (!fop.isFinished()) {
            // create a new request to send to neighbour
            System.out.println("FOP isnt finished");
            System.out.println("Curr FOP class: " + fop.getClass().getSimpleName());
            Message request;
            if (fop instanceof GetOperation || fop instanceof PutOperation)
              request = new Message(Message.MSG_GET);
            else if (KademliaCommonConfig.FINDMODE == 0)
              request = new Message(Message.MSG_FIND);
            else
              request = new Message(Message.MSG_FIND_DIST);
            request.operationId = m.operationId;
            request.src = this.getNode();
            request.dst = nodeIdtoNode(neighbour).getKademliaProtocol().getNode();
            if (KademliaCommonConfig.FINDMODE == 0 || request.getType() == Message.MSG_GET)
              request.body = fop.getDestNode();
            else
              request.body = Util.logDistance(fop.getDestNode(), (BigInteger) fop.getBody());
            // increment hop count
            fop.addHops(1);

            System.out.println("Type: " + request.typeToString());

            // send find request
            sendMessage(request, neighbour, myPid);
          }
        } else if (fop.getAvailableRequests() == KademliaCommonConfig.ALPHA) { // no new neighbour and no outstanding
                                                                               // requests - search operation finished

          System.out.println("fop finished but fop.getAvailableRequests() == KademliaCommonConfig.ALPHA is "
              + (fop.getAvailableRequests() == KademliaCommonConfig.ALPHA));

          if (fop instanceof PutOperation) {
            System.out.println("Creating a put request");
            for (BigInteger id : fop.getNeighboursList()) {
              // create a put request
              Message request = new Message(Message.MSG_PUT);
              request.operationId = m.operationId;
              request.src = this.getNode();
              request.dst = nodeIdtoNode(id).getKademliaProtocol().getNode();
              request.body = ((PutOperation) fop).getBody();
              request.value = ((PutOperation) fop).getValue();
              // increment hop count
              fop.addHops(1);
              sendMessage(request, id, myPid);
            }
            logger.warning("Sending PUT_VALUE to " + fop.getNeighboursList().size() + " nodes");
          }

          else if (fop instanceof GetOperation) {
            findOp.remove(fop.getId());
            System.out.println("Removed getOp from findOp");
            logger.warning("Getprocess finished not found ");
          }

          else if (fop instanceof RegionBasedFindOperation) {
            findOp.remove(fop.getId());
            System.out.println("Removed RBFO from findOp");
            logger.warning("Region-based lookup completed ");
          }

          else {
            findOp.remove(fop.getId());
            System.out.println("Removed " + fop.getClass() + " from findOp");
          }

          if (fop.getBody().equals("Automatically Generated Traffic")
              && fop.getClosest().containsKey(fop.getDestNode())) {
            // update statistics
            long timeInterval = (CommonState.getTime()) - (fop.getTimestamp());
            KademliaObserver.timeStore.add(timeInterval);
            KademliaObserver.hopStore.add(fop.getHops());
            KademliaObserver.msg_deliv.add(1);
            System.out.println("updated statistics");
          }

          return;

        } else { // no neighbour available but exists oustanding request to wait
          System.out.println("no neighbour available but exists oustanding request to wait");
          return;
        }
      }
    } else {
      System.err.println("There has been some error in the protocol");
    }
  }

  /**
   * Response to a put request.<br>
   * Store the object in the key value store
   *
   * @param m     Message
   * @param myPid the sender Pid
   */
  private void handlePut(Message m, int myPid) {
    BigInteger key = (BigInteger) m.body;
    BigInteger[] closestPeers = Util.getKClosestPeers(key, routingTable);

    /*
     * After finding k clostest peers, loop through ALL neighbouring nodes and send
     * a PUT msg with the message value
     */
    for (BigInteger peerId : closestPeers) {
      Message putRequest = new Message(Message.MSG_PUT);
      putRequest.src = this.getNode();
      putRequest.dst = nodeIdtoNode(peerId).getKademliaProtocol().getNode();
      putRequest.body = m.body;
      putRequest.value = m.value;
      putRequest.operationId = m.operationId;
      putRequest.ackId = m.ackId;
      sendMessage(putRequest, peerId, myPid);
    }

    // Store value locally as well
    kv.add(key, m.value);
  }

  /**
   * Response to a get request.
   * 
   * @param m     Message
   * @param myPid the sender Pid
   */
  private void handleGet(Message m, int myPid) {
    BigInteger key = (BigInteger) m.body;
    BigInteger[] closestPeers = Util.getKClosestPeers(key, routingTable);
    Object retrievedValue = kv.get(key);

    // Get k clostest peers for node and send a GET msg to each node
    for (BigInteger peerId : closestPeers) {
      Node peerNode = nodeIdtoNode(peerId);
      if (peerNode != null) {
        Message getRequest = new Message(Message.MSG_GET);
        getRequest.src = this.getNode();
        getRequest.dst = peerNode.getKademliaProtocol().getNode();
        getRequest.body = m.body;
        getRequest.operationId = m.operationId;
        getRequest.ackId = m.id;
        sendMessage(getRequest, peerId, myPid);
      } else {
        System.out.println("Peer node is null for id: " + peerId);
      }
    }

    /*
     * If a value has been retreived, then send a RESPONSE msg with the retrieved
     * value.
     * 
     * This is IS NECESSARY, CANNOT REMOVE IT SINCE PREVIOUS IMPLEMETATIONS NEEDED A
     * RESPONSE MSG, see handleFind for prev code
     */
    if (retrievedValue != null) {
      Message response = new Message(Message.MSG_RESPONSE, closestPeers);
      response.operationId = m.operationId;
      response.dst = m.dst;
      response.src = this.getNode();
      response.value = retrievedValue;
      response.ackId = m.id;
      sendMessage(response, m.src.getId(), myPid);
    } else {
      System.out.println("Value not found locally for key: " + key);
    }
  }

  /**
   * Response to a route request.<br>
   * Find the ALPHA closest node consulting the k-buckets and return them to the
   * sender.
   *
   * @param m     Message
   * @param myPid the sender Pid
   */

  private void handleFind(Message m, int myPid) {

    logger.info("handleFind received from " + m.src.getId() + " " + m.operationId);
    BigInteger[] neighbours;

    // System.out.println("Message toString: " + m.toString());
    // System.out.println("Node is " + this.node.isEvil());

    if (m.getType() == Message.MSG_FIND || m.getType() == Message.MSG_GET) {
      neighbours = this.routingTable.getNeighbours((BigInteger) m.body, m.src.getId());
    } else if (m.getType() == Message.MSG_FIND_DIST) {
      neighbours = this.routingTable.getNeighbours((int) m.body);
    } else if (m.getType() == Message.MSG_FIND_REGION_BASED) {
      neighbours = this.routingTable.getNeighbours((BigInteger) m.body, m.src.getId());
    } else {
      logger.warning("Unsupported message type: " + m.getType());
      return;
    }

    // System.out.println("Message Routing Table: " + Arrays.toString(neighbours));

    Message response = new Message(Message.MSG_RESPONSE, neighbours);
    response.operationId = m.operationId;
    response.dst = m.dst;
    response.src = this.getNode();
    response.ackId = m.id;

    if (m.getType() == Message.MSG_GET) {
      response.value = kv.get((BigInteger) m.body);
    }

    sendMessage(response, m.src.getId(), myPid);
  }

  /**
   * Start a find node opearation.<br>
   * Find the ALPHA closest node and send find request to them.
   *
   * @param m     Message received (contains the node to find)
   * @param myPid the sender Pid
   */
  private void handleInit(Message m, int myPid) {
    // NEED TO REVIEW THIS
    logger.info("handleInitFind " + (m.body instanceof BigInteger ? (BigInteger) m.body : (int) m.body));
    KademliaObserver.find_op.add(1);

    // create find operation and add to operations array
    // FindOperation fop = new FindOperation(m.dest, m.timestamp);

    FindOperation fop;
    switch (m.type) {
      case Message.MSG_INIT_FIND_REGION_BASED:
        fop = new RegionBasedFindOperation(this.node.getId(), (BigInteger) m.body, (int) m.value, m.timestamp);
        break;
      case Message.MSG_INIT_FIND:
        fop = new FindOperation(this.node.getId(), (BigInteger) m.body, m.timestamp);
        break;
      case Message.MSG_INIT_GET:
        fop = new GetOperation(this.node.getId(), (BigInteger) m.body, m.timestamp);
        break;
      case Message.MSG_INIT_PUT:
        fop = new PutOperation(this.node.getId(), (BigInteger) m.body, m.timestamp);
        ((PutOperation) fop).setValue(m.value);
        break;
      default:
        fop = new FindOperation(this.node.getId(), (BigInteger) BigInteger.valueOf((int) m.body), m.timestamp);
        break;
    }

    fop.setBody(m.body);
    findOp.put(fop.getId(), fop);

    // get the ALPHA closest node to srcNode and add to find operation
    BigInteger[] neighbours = this.routingTable.getNeighbours((BigInteger) m.body, this.getNode().getId());
    fop.elaborateResponse(neighbours);
    fop.setAvailableRequests(KademliaCommonConfig.ALPHA);

    // set message operation id
    m.operationId = fop.getId();

    m.src = this.getNode();

    // send ALPHA messages
    for (int i = 0; i < KademliaCommonConfig.ALPHA; i++) {
      BigInteger nextNode = fop.getNeighbour();
      if (nextNode != null) {
        m.dst = nodeIdtoNode(nextNode).getKademliaProtocol().getNode(); // new KademliaNode(nextNode);
        // set message type depending on find mode
        if (m.type == Message.MSG_INIT_GET)
          m.type = Message.MSG_GET;
        else if (KademliaCommonConfig.FINDMODE == 0)
          m.type = Message.MSG_FIND;
        else if (m.type == Message.MSG_INIT_FIND_REGION_BASED) {
          m.type = Message.MSG_FIND_REGION_BASED;
        } else if (m.type == Message.MSG_INIT_PUT) {
          m.type = Message.MSG_PUT;
        } else {
          m.type = Message.MSG_FIND_DIST;
          m.body = Util.logDistance(nextNode, (BigInteger) fop.getBody());
        }

        logger.info("sendMessage to " + nextNode);

        sendMessage(m.copy(), nextNode, myPid);
        fop.addHops(1);
      }
    }
  }

  /**
   * send a message with current transport layer and starting the timeout timer
   * (wich is an event)
   * if the message is a request
   *
   * @param m      the message to send
   * @param destId the Id of the destination node
   * @param myPid  the sender Pid
   */
  public void sendMessage(Message m, BigInteger destId, int myPid) {
    // add destination to routing table
    this.routingTable.addNeighbour(destId);
    // int destpid;
    assert m.src != null;
    assert m.dst != null;

    Node src = nodeIdtoNode(this.getNode().getId());
    Node dest = nodeIdtoNode(destId);

    // destpid = dest.getKademliaProtocol().getProtocolID();

    transport = (UnreliableTransport) (Network.prototype).getProtocol(tid);
    transport.send(src, dest, m, kademliaid);

    if (m.getType() == Message.MSG_FIND || m.getType() == Message.MSG_FIND_DIST) { // is a request
      Timeout t = new Timeout(destId, m.id, m.operationId);
      long latency = transport.getLatency(src, dest);

      // add to sent msg
      this.sentMsg.put(m.id, m.timestamp);
      EDSimulator.add(4 * latency, t, src, myPid); // set delay = 2*RTT
    }
  }

  /**
   * manage the peersim receiving of the events
   *
   * @param myNode Node
   * @param myPid  int
   * @param event  Object
   */
  public void processEvent(Node myNode, int myPid, Object event) {

    // Parse message content Activate the correct event manager fot the particular
    // event
    this.kademliaid = myPid;

    Message m;
    if (event instanceof Message) {
      m = (Message) event;
      KademliaObserver.reportMsg(m, false);
    }

    switch (((SimpleEvent) event).getType()) {
      case Message.MSG_RESPONSE:
        m = (Message) event;
        sentMsg.remove(m.ackId);
        handleResponse(m, myPid);
        break;

      case Message.MSG_INIT_FIND:
      case Message.MSG_INIT_GET:
      case Message.MSG_INIT_PUT:
        m = (Message) event;
        handleInit(m, myPid);
        break;

      case Message.MSG_FIND:
      case Message.MSG_FIND_DIST:
        m = (Message) event;
        handleFind(m, myPid);
        break;
      case Message.MSG_INIT_FIND_REGION_BASED:
        m = (Message) event;
        handleInit(m, myPid);
        break;
      case Message.MSG_FIND_REGION_BASED:
        m = (Message) event;
        handleFind(m, myPid);
        break;
      case Message.MSG_GET:
        m = (Message) event;
        handleGet(m, myPid);
        break;

      case Message.MSG_PUT:
        m = (Message) event;
        handlePut(m, myPid);
        break;

      case Message.MSG_EMPTY:
        // TO DO
        break;

      case Message.MSG_STORE:
        // TO DO
        break;

      /*
       * case Timeout.TIMEOUT: // timeout
       * Timeout t = (Timeout) event;
       * if (sentMsg.containsKey(t.msgID)) { // the response msg isn't arrived
       * // remove form sentMsg
       * sentMsg.remove(t.msgID);
       * // remove node from my routing table
       * this.routingTable.removeNeighbour(t.node);
       * // remove from closestSet of find operation
       * this.findOp.get(t.opID).closestSet.remove(t.node);
       * // try another node
       * Message m1 = new Message();
       * m1.operationId = t.opID;
       * m1.src = getNode();
       * m1.dest = this.findOp.get(t.opID).destNode;
       * this.handleResponse(m1, myPid);
       * }
       * break;
       */
    }
  }

  /** get the current Node */
  public KademliaNode getNode() {
    return this.node;
  }

  /** get the kademlia node routing table */
  public RoutingTable getRoutingTable() {
    return this.routingTable;
  }

  /** Set the protocol ID for this node. */
  public void setProtocolID(int protocolID) {
    this.kademliaid = protocolID;
  }

  /**
   * set the current NodeId
   *
   * @param tmp BigInteger
   */
  public void setNode(KademliaNode node) {
    this.node = node;
    this.routingTable.setNodeId(node.getId());

    logger = Logger.getLogger(node.getId().toString());
    logger.setUseParentHandlers(false);
    ConsoleHandler handler = new ConsoleHandler();
    logger.setLevel(Level.WARNING);
    // logger.setLevel(Level.ALL);

    handler.setFormatter(
        new SimpleFormatter() {
          private static final String format = "[%d][%s] %3$s %n";

          @Override
          public synchronized String format(LogRecord lr) {
            return String.format(format, CommonState.getTime(), logger.getName(), lr.getMessage());
          }
        });
    logger.addHandler(handler);
  }
}