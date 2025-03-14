package peersim.kademlia;

/**
 * A Kademlia implementation for PeerSim extending the EDProtocol class.<br>
 * See the Kademlia bibliografy for more information about the protocol.
 *
 * @author Daniele Furlan, Maurizio Bonani
 * @version 1.0
 */
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
// logging
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
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

  private double dynamicThreshold = 0.0;
  private double smoothingFactor = 0.5; // Determines how fast threshold adapts
  private Set<BigInteger> detectedSybils = new HashSet<>();

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
      // System.out.println("mID: " + mId + "| Search Node: " + searchNodeId);
      if (mId.equals(searchNodeId))
        return Network.get(i);
    }

    // System.err.println(
    // "Error: Node with ID " + searchNodeId + " not found in network! Current
    // network size: " + Network.size());
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
  private void handleResponse(Message m, int myPid) {
    // add message source to my routing table
    if (m.src != null) {
      routingTable.addNeighbour(m.src.getId());
    }

    // get corresponding find operation (using the message field operationId)
    FindOperation fop = this.findOp.get(m.operationId);

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
        // System.out.println("Got value : " + m.value);
        logger.warning(
            "Getprocess finished found " + ((GetOperation) fop).getValue() + " hops " + fop.getHops());
      }

      if (fop instanceof GetOperation && m.value == null) {
        if (m.value != null) {
          Message response = new Message(Message.MSG_RESPONSE);
          response.operationId = fop.getId();
          response.dst = m.src;
          response.src = this.getNode();
          response.body = m.body;
          response.value = m.value;
          response.ackId = m.ackId;

          sendMessage(response, m.src.getId(), myPid);
          return;
        }

        for (BigInteger id : fop.getNeighboursList()) {
          Message getRequest = new Message(Message.MSG_GET);
          getRequest.src = this.getNode();
          getRequest.dst = nodeIdtoNode(id).getKademliaProtocol().getNode();
          getRequest.body = fop.getDestNode();
          getRequest.operationId = fop.getId();

          sendMessage(getRequest, id, myPid);
        }
        return;
      }

      while (fop.getAvailableRequests() > 0) { // I can send a new find request

        // get an available neighbour
        BigInteger neighbour = fop.getNeighbour();
        if (neighbour != null) {
          if (!fop.isFinished()) {
            Message request;
            if (fop instanceof GetOperation)
              request = new Message(Message.MSG_GET);
            else if (KademliaCommonConfig.FINDMODE == 0)
              request = new Message(Message.MSG_FIND);
            else if (fop instanceof RegionBasedFindOperation)
              request = new Message(Message.MSG_FIND_REGION_BASED);
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

            // send find request
            sendMessage(request, neighbour, myPid);
          }
        } else if (fop.getAvailableRequests() == KademliaCommonConfig.ALPHA) { // no new neighbour and no outstanding
                                                                               // requests
          // search operation finished
          if (fop instanceof PutOperation) {
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
          } else if (fop instanceof GetOperation) {
            findOp.remove(fop.getId());
            System.out.println("removed fop bc of getOp");
            logger.warning("Getprocess finished not found ");

          } else if (fop instanceof RegionBasedFindOperation) {
            findOp.remove(fop.getId());
            logger.warning("Region-based lookup completed ");
          } else {
            System.out.println("removed fop in general");
            findOp.remove(fop.getId());
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

    if (MaliciousCustomDistribution.knownMaliciousNodes.contains(this.node.getId())) {
      System.out.println("Attempted to store data on malicious node: " + this.node.getId() + ". Selecting a new node.");

      // Find a new honest node
      BigInteger newNode = findNewHonestNode();
      if (newNode != null) {
        System.out.println("Redirecting storage to honest node: " + newNode);
        Node targetNode = nodeIdtoNode(newNode);
        if (targetNode != null) {
          KademliaProtocol targetProtocol = (KademliaProtocol) targetNode.getProtocol(myPid);
          targetProtocol.kv.add(key, m.value);
        }
      } else {
        System.out.println("No suitable honest node found. Skipping storage.");
      }
    } else {
      kv.add(key, m.value);
      System.out.println("Data stored successfully on honest node: " + this.node.getId());
    }

    PutOperation putOp = new PutOperation(this.node.getId(), key, CommonState.getTime());
    putOp.setValue(m.value);
    putOp.setBody(key);
    putOp.setAvailableRequests(KademliaCommonConfig.ALPHA);
    putOp.setFinished(false);

    // BigInteger[] initialNeighbours = this.routingTable.getNeighbours(key,
    // this.node.getId());
    // putOp.elaborateResponse(initialNeighbours);

    findOp.put(putOp.getId(), putOp);

    for (int i = 0; i < KademliaCommonConfig.ALPHA; i++) {
      BigInteger nextNode = putOp.getNeighbour();
      if (nextNode != null) {
        Message findRequest = new Message(Message.MSG_FIND);
        findRequest.src = this.getNode();
        findRequest.body = key;
        findRequest.operationId = putOp.getId();
        findRequest.dst = nodeIdtoNode(nextNode).getKademliaProtocol().getNode();

        sendMessage(findRequest, nextNode, myPid);
      }
    }

    for (BigInteger id : putOp.getNeighboursList()) {
      Message putRequest = new Message(Message.MSG_PUT);
      putRequest.src = this.getNode();
      putRequest.dst = nodeIdtoNode(id).getKademliaProtocol().getNode();
      putRequest.body = key;
      putRequest.value = putOp.getValue();
      putRequest.operationId = putOp.getId();

      sendMessage(putRequest, id, myPid);
    }
  }

  /**
   * Response to a get request.
   * 
   * @param m     Message
   * @param myPid the sender Pid
   */
  private void handleGet(Message m, int myPid) {
    if (this.node.isEvil()) {
      System.out.println("Malicious node " + this.node.getId() + " ignored GET request.");
      return; // Ignore the request
    }
    BigInteger key = (BigInteger) m.body;
    Object retrievedValue = kv.get(key);

    if (retrievedValue != null) {
      Message response = new Message(Message.MSG_RESPONSE);
      response.operationId = m.operationId;
      response.dst = m.src;
      response.src = this.getNode();
      response.body = new BigInteger[] { key };
      response.value = retrievedValue;
      response.ackId = m.ackId;

      sendMessage(response, m.src.getId(), myPid);
      return;
    }

    GetOperation getOp = new GetOperation(this.node.getId(), key, CommonState.getTime());
    getOp.setBody(key);
    getOp.setAvailableRequests(KademliaCommonConfig.ALPHA);
    getOp.setFinished(false);

    findOp.put(getOp.getId(), getOp);

    for (int i = 0; i < KademliaCommonConfig.ALPHA; i++) {
      BigInteger nextNode = getOp.getNeighbour();
      if (nextNode != null) {
        Message findRequest = new Message(Message.MSG_FIND);
        findRequest.src = this.getNode();
        findRequest.body = key;
        findRequest.operationId = getOp.getId();
        findRequest.dst = nodeIdtoNode(nextNode).getKademliaProtocol().getNode();

        sendMessage(findRequest, nextNode, myPid);
      }
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
    if (this.node.isEvil()) {
      System.out.println("Malicious node " + this.node.getId() + " ignored FIND request.");
      return; // Ignore the request
    }

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

    // get the ALPHA closest node to srcNode and add to find operation
    BigInteger[] neighbours = this.routingTable.getNeighbours((BigInteger) m.body, this.getNode().getId());
    fop.elaborateResponse(neighbours);
    fop.setAvailableRequests(KademliaCommonConfig.ALPHA);
    fop.setBody(m.body);
    findOp.put(fop.getId(), fop);
    // set message operation id
    m.operationId = fop.getId();

    m.src = this.getNode();

    detectSybilAttack((BigInteger) m.body);

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
        // m = (Message) event;
        // handleInit(m, myPid);
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

  // -----------
  // -----------
  // -----------
  // -----------
  // -----------
  // _________
  // Detection
  // _________
  // -----------
  // -----------
  // -----------
  // -----------
  // -----------

  /**
   * Detects potential Sybil attacks based on the distribution of peer IDs.
   *
   * @param targetCID The content identifier (CID) being queried.
   */
  public void detectSybilAttack(BigInteger targetCID) {
    // Validate that the targetCID exists in the network
    Node targetNode = nodeIdtoNode(targetCID);

    if (targetNode != null) {
      // Check if the target CID is already flagged as Sybil
      // If true then run mitigation
      if (detectedSybils.contains(targetCID)) {
        mitigateContentCensorship(targetCID);
        return;
      }

      // Step 1: Get 20 closest peers to targetCID
      List<BigInteger> closestPeers = getClosestPeers(targetCID, KademliaCommonConfig.K);
      if (closestPeers.size() < KademliaCommonConfig.K) {
        System.out.println("Insufficient peers for analysis.");
        return;
      }

      // Step 2: Compute observed distribution q
      Map<Integer, Integer> cplCount = new HashMap<>();
      for (BigInteger peerId : closestPeers) {
        int cpl = Util.prefixLen(targetCID, peerId);
        cplCount.put(cpl, cplCount.getOrDefault(cpl, 0) + 1);
      }

      // Normalize q
      Map<Integer, Double> q = new HashMap<>();
      for (Map.Entry<Integer, Integer> entry : cplCount.entrySet()) {
        q.put(entry.getKey(), entry.getValue() / (double) KademliaCommonConfig.K);
      }

      // Step 3 & 4: Estimate network size & compute expected distribution
      Map<Integer, Double> p = computeExpectedDistribution(Network.size());

      // Step 5: Compute KL divergence
      double klDivergence = computeKLDivergence(p, q);

      // Update threshold dynamically
      updateDynamicThreshold(klDivergence);

      // Step 6: Check if KL divergence exceeds threshold
      if (klDivergence > dynamicThreshold) {
        detectedSybils.add(targetCID);
        System.out.println("Confirmed Sybil attack on " + targetCID + ". Applying mitigation.");
        mitigateContentCensorship(targetCID);
      } else {
        System.out.println("No Sybil attack detected on " + targetCID + ".");
      }
    }
  }

  /**
   * Updates the dynamic threshold for attack detection
   * 
   * @param newKLDivergence The KL divergence value to update
   */
  private void updateDynamicThreshold(double newKLDivergence) {
    // Apply exponential smoothing to adjust the detection threshold dynamically
    dynamicThreshold = (smoothingFactor * newKLDivergence) + ((1 - smoothingFactor) * dynamicThreshold);
  }

  /**
   * Retrieves the K closest peers to the target content identifier (CID).
   * 
   * @param targetCID The CID being queried.
   * @param numPeers  The number of closest peers to retrieve.
   * @return A list of the closest peer IDs.
   */
  private List<BigInteger> getClosestPeers(BigInteger targetCID, int numPeers) {
    // Query the routing table to get the closest peers to the target CID
    BigInteger[] neighbors = this.routingTable.getNeighbours(targetCID, this.node.getId());
    List<BigInteger> closestPeers = new ArrayList<>();
    for (int i = 0; i < Math.min(numPeers, neighbors.length); i++) {
      closestPeers.add(neighbors[i]);
    }
    return closestPeers;
  }

  /**
   * Computes the expected distribution of Common Prefix Lengths (CPLs).
   *
   * @param networkSize The estimated size of the network.
   * @return A map of CPL to its expected probability.
   */
  private Map<Integer, Double> computeExpectedDistribution(int networkSize) {
    Map<Integer, Double> p = new HashMap<>();

    // Estimate the bit-length of node IDs based on network size
    int m = (int) (Math.log(networkSize) / Math.log(2));

    // Compute the expected probability for each CPL value using 2^(-i)
    for (int i = 0; i <= m; i++) {
      p.put(i, Math.pow(2, -i));
    }
    return p;
  }

  /**
   * Computes the Kullback-Leibler (KL) Divergence between two distributions.
   *
   * @param p The expected distribution.
   * @param q The observed distribution.
   * @return The KL divergence value.
   */
  private double computeKLDivergence(Map<Integer, Double> p, Map<Integer, Double> q) {
    double klDiv = 0.0;

    // Iterate through all expected CPL values and compute divergence
    for (Map.Entry<Integer, Double> entry : p.entrySet()) {
      int cpl = entry.getKey();
      double pValue = entry.getValue();

      // Use a small value (1e-10) to prevent log(0) errors in case q lacks a CPL
      double qValue = q.getOrDefault(cpl, 1e-10);

      // Compute KL divergence: D_KL(P || Q) = Σ P(i) * log(P(i) / Q(i))
      klDiv += pValue * Math.log(pValue / qValue);
    }
    return klDiv;
  }

  // -----------
  // -----------
  // -----------
  // -----------
  // -----------
  // __________
  // Mitigation
  // __________
  // -----------
  // -----------
  // -----------
  // -----------
  // -----------

  public void mitigateContentCensorship(BigInteger contentId) {
    System.out.println("Initiating region-based lookup for mitigation of content censorship on: " + contentId);

    // Step 1: Start a region-based find operation
    RegionBasedFindOperation findOp = new RegionBasedFindOperation(this.node.getId(), contentId, KademliaCommonConfig.K,
        CommonState.getTime());
    BigInteger[] initialNeighbours = this.routingTable.getNeighbours(contentId, this.node.getId());
    findOp.elaborateResponse(initialNeighbours);
    findOp.setAvailableRequests(KademliaCommonConfig.ALPHA);
    findOp.setBody(contentId);
    this.findOp.put(findOp.getId(), findOp);

    // Step 2: Send initial FIND_REGION_BASED messages to ALPHA nodes
    for (int i = 0; i < KademliaCommonConfig.ALPHA; i++) {
      BigInteger nextNode = findOp.getNeighbour();
      if (nextNode != null) {
        Message request = new Message(Message.MSG_FIND_REGION_BASED);
        request.operationId = findOp.getId();
        request.src = this.getNode();
        request.dst = nodeIdtoNode(nextNode).getKademliaProtocol().getNode();
        request.body = contentId;
        sendMessage(request, nextNode, this.kademliaid);
        findOp.addHops(1);
      }
    }

    // Step 3: Collect honest nodes from the regional set
    Set<BigInteger> honestNodes = new HashSet<>();
    for (BigInteger node : findOp.regionalSet.keySet()) {
      if (!detectedSybils.contains(node)) { // Only select honest nodes
        honestNodes.add(node);
      }
    }

    // Step 4: Attempt to contact honest nodes for content retrieval
    for (BigInteger honestNode : honestNodes) {
      Message getRequest = new Message(Message.MSG_GET);
      getRequest.src = this.getNode();
      getRequest.dst = nodeIdtoNode(honestNode).getKademliaProtocol().getNode();
      getRequest.body = contentId;
      sendMessage(getRequest, honestNode, this.kademliaid);
    }
  }

  private BigInteger findNewHonestNode() {
    List<BigInteger> allNodes = getAllKnownNodes();
    for (BigInteger nodeId : allNodes) {
      if (!MaliciousCustomDistribution.knownMaliciousNodes.contains(nodeId)) {
        return nodeId; // Return the first honest node found
      }
    }
    return null; // No honest node found
  }

  private List<BigInteger> getAllKnownNodes() {
    List<BigInteger> allNodes = new ArrayList<>();
    for (int i = 0; i <= routingTable.nBuckets; i++) {
      allNodes.addAll(routingTable.k_buckets.get(i).neighbours.keySet());
    }
    return allNodes;
  }

}