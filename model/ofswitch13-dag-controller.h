/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Luciano Chaves <luciano@lrc.ic.unicamp.br>
 */

#ifndef OFSWITCH13_DAG_CONTROLLER_H
#define OFSWITCH13_DAG_CONTROLLER_H

#include "ofswitch13-controller.h"
#include <ns3/subgraph.h>
#include "ns3/data-rate.h"
#include "ns3/ipv4-interface-container.h"
#include <list>

namespace ns3 {

/**
 * \ingroup ofswitch13
 * \brief An OpenFlow 1.3 controller enforcing DAG based routing
 */
class OFSwitch13DagController : public OFSwitch13Controller
{
public:
  OFSwitch13DagController ();          //!< Default constructor
  virtual ~OFSwitch13DagController (); //!< Dummy destructor.

  /**
   * Register this type.
   * \return The object TypeId.
   */
  static TypeId GetTypeId (void);

  /** Destructor implementation */
  virtual void DoDispose ();

  /**
   * Handle packet-in messages sent from switch to this controller. Look for L2
   * switching information, update the structures and send a packet-out back.
   *
   * \param msg The packet-in message.
   * \param swtch The switch information.
   * \param xid Transaction id.
   * \return 0 if everything's ok, otherwise an error number.
   */
  ofl_err HandlePacketIn (
    struct ofl_msg_packet_in *msg, Ptr<const RemoteSwitch> swtch,
    uint32_t xid);

  /**
   * Handle flow removed messages sent from switch to this controller. Look for
   * L2 switching information and removes associated entry.
   *
   * \param msg The flow removed message.
   * \param swtch The switch information.
   * \param xid Transaction id.
   * \return 0 if everything's ok, otherwise an error number.
   */
  ofl_err HandleFlowRemoved (
    struct ofl_msg_flow_removed *msg, Ptr<const RemoteSwitch> swtch,
    uint32_t xid);

  /**
   * set the minimum number of switches that need to be connected after invoking
   * a topology update.
   */
  void SetMinNSwitches (uint16_t count);

  /**
   * set the demands.
   */
  void SetDemands (std::map<std::pair<uint16_t,uint16_t>,double> demands);

  /**
   * Return the active path followed by the given flow
   */
  std::vector<uint16_t> GetActivePathForFlow (Ipv4Address srcIp, Ipv4Address dstIp,
                                              uint8_t protocol,
                                              uint16_t srcPort, uint16_t dstPort);

protected:
  // Inherited from OFSwitch13Controller
  void HandshakeSuccessful (Ptr<const RemoteSwitch> swtch);

  /**
   * (Re-)computes the network topology.
   */
  void UpdateTopology (void);

private:
  ofl_err HandleArpPacketIn (
    struct ofl_msg_packet_in *msg, Ptr<const RemoteSwitch> swtch,
    uint32_t xid);

  /**
   * Run RDAS between nodes s and d
   * \param s source node
   * \param d destination node
   */
  void FindLooplessResilientDAG (uint16_t s, uint16_t d);

  /**
   * Solve an LP to minimize the maximum utilization across all the links
   * \return the maximum utilization
   */
  double MinimizeMaxUtilization (void);

  /**
   * Solve an LP to maximize the minimum flow (for a single demand) across all the links,
   * subject to the constraint that the utilization of each link does not exceed the given
   * maximum utilization
   * \param maxUtil the maximum utilization
   */
  void MaximizeMinFlow (double maxUtil);

  struct Demand;

  /**
   * Install flow entries and group entries for all the demands
   */
  void InstallEntries (void);

  /**
   * Check if the assignment of neighbors to bins need to be updated
   */
  void UpdateNeighborsToBinsAssignment (void);

  /**
   * Compute the bins for the given node and the given demand
   */
  std::vector<uint16_t> ComputeBinsLP (uint16_t node, std::pair<uint16_t,uint16_t> d);

  /**
   * Return the link cost (1/avail_bw)
   */
  double InverseBwd (uint16_t u, uint16_t v);

  uint16_t m_numSwitches;       //!< the topology is updated once this number of switches are connected
  uint16_t m_nBins;             //!< the number of bins (or, equivalently, paths) per DAG


  /**
   * \name DAG based routing structures
   */
  //\{
  /** Neighbor info */
  struct Neighbor
  {
    uint64_t m_dpId;             //!< The datapath id of the neighbor
    uint32_t m_portNo;           //!< The number of the local port connected to the neighbor
    Ptr<NetDevice> m_localDev;   //!< The local netdevice
    Ptr<NetDevice> m_remoteDev;  //!< The remote netdevice
    DataRate m_capacity;         //!< The capacity of the link
    DataRate m_flow;             //!< The currently allocated flow
  };

  struct Demand
  {
    double m_bwd;                //!< The requested bandwidth
    Linklist m_linkList;         //!< The list of links included in the DAG
    std::vector<std::list<uint16_t>> m_paths;   //!< The list of used paths within the DAG
    uint32_t m_label;            //!< MPLS label
  };

  struct Host
  {
    uint32_t m_portNo;           //!< The number of the port on the edge switch
    Ipv4Address m_ipAddress;     //!< The IPv4 address of the host
    Mac48Address m_macAddress;   //!< The MAC address of the host
  };

  /** Neighbor list */
  typedef std::list<Neighbor> NeighborList;

  /** Topology: map datapathID to NeighborList */
  typedef std::map<uint64_t, NeighborList> Topology;

  /** Switching information for all dapataths */
  Topology m_topology;

  /** Maps each edge switch to the connected host */
  std::map<uint64_t,Host> m_edges;

  /** demands */
  std::map<std::pair<uint16_t,uint16_t>,Demand> m_demands;     // node IDs start at 0
  
  // maps (datapathID,demand) pairs to the groupID of the corresponding group entry
  std::map<std::pair<uint64_t,std::pair<uint16_t,uint16_t>>, uint16_t> m_groupIDs;

  // m_Bucket[i][{s,d}] is the bucket of node i for demand (s,d)
  std::vector<std::map<std::pair<uint16_t,uint16_t>,std::vector<uint16_t> > > m_Bucket;

  /** RDAS' alpha parameter */
  double m_alpha;

  /** Period for updating neighbors to bin assignment (seconds) */
  double m_period;
  
  /** LP results: map demands to vector of link flows (in the same order as m_linkList) */
  std::map<std::pair<uint16_t,uint16_t>,std::vector<double> > m_ptrVar;
  //\}

};

} // namespace ns3
#endif /* OFSWITCH13_DAG_CONTROLLER_H */
