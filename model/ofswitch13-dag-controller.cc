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

#ifdef NS3_OFSWITCH13

#include "ofswitch13-dag-controller.h"
#include "ofswitch13-device.h"
#include <ns3/dag.h>
#include <ns3/arp-l3-protocol.h>
#include <ns3/arp-header.h>
#include <ns3/ethernet-header.h>
#include <ns3/ethernet-trailer.h>
#include <ksp/YenTopKShortestPathsAlg.h>
#include <ksp/DijkstraShortestPathAlg.h>
#include <algorithm>
#include <coin/ClpSimplex.hpp>
#include <coin/CoinBuild.hpp>
#include <numeric>
#include <iterator>

NS_LOG_COMPONENT_DEFINE ("OFSwitch13DagController");

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED (OFSwitch13DagController);

/********** Public methods ***********/
OFSwitch13DagController::OFSwitch13DagController ()
{
  NS_LOG_FUNCTION (this);
}

OFSwitch13DagController::~OFSwitch13DagController ()
{
  NS_LOG_FUNCTION (this);
}

TypeId
OFSwitch13DagController::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::OFSwitch13DagController")
    .SetParent<OFSwitch13Controller> ()
    .SetGroupName ("OFSwitch13")
    .AddConstructor<OFSwitch13DagController> ()
    .AddAttribute ("NSwitches",
                   "Minimum number of connected devices to update the topology.",
                   UintegerValue (1),
                   MakeUintegerAccessor (&OFSwitch13DagController::m_numSwitches),
                   MakeUintegerChecker<uint16_t> ())
    .AddAttribute ("NBins",
                   "Number of bins (or, equivalently, paths) per DAG.",
                   UintegerValue (10),
                   MakeUintegerAccessor (&OFSwitch13DagController::m_nBins),
                   MakeUintegerChecker<uint16_t> ())
    .AddAttribute ("alpha",
                   "RDAS' alpha parameter.",
                   DoubleValue (1.5),
                   MakeDoubleAccessor (&OFSwitch13DagController::m_alpha),
                   MakeDoubleChecker<double> ())
    .AddAttribute ("period",
                   "Period for updating neighbors to bin assignment (seconds).",
                   DoubleValue (5),
                   MakeDoubleAccessor (&OFSwitch13DagController::m_period),
                   MakeDoubleChecker<double> ())
  ;
  return tid;
}

void
OFSwitch13DagController::DoDispose ()
{
  NS_LOG_FUNCTION (this);

  OFSwitch13Controller::DoDispose ();
}

ofl_err
OFSwitch13DagController::HandlePacketIn (
  struct ofl_msg_packet_in *msg, Ptr<const RemoteSwitch> swtch,
  uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  char *msgStr =
    ofl_structs_match_to_string ((struct ofl_match_header*)msg->match, 0);
  NS_LOG_DEBUG ("Packet in match: " << msgStr);
  free (msgStr);

//   if (msg->reason == OFPR_ACTION)
    {
      // Get Ethernet frame type
      uint16_t ethType;
      struct ofl_match_tlv *tlv;
      tlv = oxm_match_lookup (OXM_OF_ETH_TYPE, (struct ofl_match*)msg->match);
      memcpy (&ethType, tlv->value, OXM_LENGTH (OXM_OF_ETH_TYPE));

      if (ethType == ArpL3Protocol::PROT_NUMBER)
        {
          // ARP packet
          return HandleArpPacketIn (msg, swtch, xid);
        }
    }

  NS_LOG_WARN ("This controller (" << swtch->GetDpId () << ") can't handle the packet. Unkwnon reason.");

  // All handlers must free the message when everything is ok
  ofl_msg_free ((struct ofl_msg_header*)msg, 0);
  return 0;
}

ofl_err
OFSwitch13DagController::HandleFlowRemoved (
  struct ofl_msg_flow_removed *msg, Ptr<const RemoteSwitch> swtch,
  uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  NS_FATAL_ERROR ( "Flow entry expired!!!");

  // All handlers must free the message when everything is ok
  ofl_msg_free_flow_removed (msg, true, 0);
  return 0;
}


Ipv4Address
ExtractIpv4Address (uint64_t oxm_of, struct ofl_match* match)
{
  switch (oxm_of)
    {
    case (uint64_t)OXM_OF_ARP_SPA:
    case (uint64_t)OXM_OF_ARP_TPA:
    case (uint64_t)OXM_OF_IPV4_DST:
    case (uint64_t)OXM_OF_IPV4_SRC:
      {
        uint32_t ip;
        int size = OXM_LENGTH (oxm_of);
        struct ofl_match_tlv *tlv = oxm_match_lookup (oxm_of, match);
        memcpy (&ip, tlv->value, size);
        return Ipv4Address (ntohl (ip));
      }
    default:
      NS_FATAL_ERROR ("Invalid IP field.");
    }
}

Ptr<Packet>
CreateArpReply (Mac48Address srcMac, Ipv4Address srcIp,
                Mac48Address dstMac, Ipv4Address dstIp)
{
  Ptr<Packet> packet = Create<Packet> ();

  // ARP header
  ArpHeader arp;
  arp.SetReply (srcMac, srcIp, dstMac, dstIp);
  packet->AddHeader (arp);

  // Ethernet header
  EthernetHeader eth (false);
  eth.SetSource (srcMac);
  eth.SetDestination (dstMac);
  if (packet->GetSize () < 46)
    {
      uint8_t buffer[46];
      memset (buffer, 0, 46);
      Ptr<Packet> padd = Create<Packet> (buffer, 46 - packet->GetSize ());
      packet->AddAtEnd (padd);
    }
  eth.SetLengthType (ArpL3Protocol::PROT_NUMBER);
  packet->AddHeader (eth);

  // Ethernet trailer
  EthernetTrailer trailer;
  if (Node::ChecksumEnabled ())
    {
      trailer.EnableFcs (true);
    }
  trailer.CalcFcs (packet);
  packet->AddTrailer (trailer);

  return packet;
}


ofl_err
OFSwitch13DagController::HandleArpPacketIn (
  struct ofl_msg_packet_in *msg, Ptr<const RemoteSwitch> swtch,
  uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  struct ofl_match_tlv *tlv;
  Mac48Address targetMac;

  // Get ARP operation
  uint16_t arpOp;
  tlv = oxm_match_lookup (OXM_OF_ARP_OP, (struct ofl_match*)msg->match);
  memcpy (&arpOp, tlv->value, OXM_LENGTH (OXM_OF_ARP_OP));

  // Get input port
  uint32_t inPort;
  tlv = oxm_match_lookup (OXM_OF_IN_PORT, (struct ofl_match*)msg->match);
  memcpy (&inPort, tlv->value, OXM_LENGTH (OXM_OF_IN_PORT));

  // Get source and target IP address
  Ipv4Address srcIp, dstIp;
  srcIp = ExtractIpv4Address (OXM_OF_ARP_SPA, (struct ofl_match*)msg->match);
  dstIp = ExtractIpv4Address (OXM_OF_ARP_TPA, (struct ofl_match*)msg->match);

  // Get Source MAC address
  Mac48Address srcMac, dstMac;
  tlv = oxm_match_lookup (OXM_OF_ARP_SHA, (struct ofl_match*)msg->match);
  srcMac.CopyFrom (tlv->value);
  tlv = oxm_match_lookup (OXM_OF_ARP_THA, (struct ofl_match*)msg->match);
  dstMac.CopyFrom (tlv->value);

  // Check for ARP request
  if (arpOp == ArpHeader::ARP_TYPE_REQUEST)
    {
      uint8_t replyData[64];
      bool found = false;

      // find the host in the data structure
      for (auto& host : m_edges)
        {
          if (host.second.m_ipAddress == dstIp)
            {
              targetMac = host.second.m_macAddress;
              found = true;
              break;
            }
        }
      NS_ASSERT_MSG (found, "Host not found!");

      // Reply with IP/MAC addresses
      Ptr<Packet> pkt = CreateArpReply (targetMac, dstIp, srcMac, srcIp);
      NS_ASSERT_MSG (pkt->GetSize () == 64, "Invalid packet size.");
      pkt->CopyData (replyData, 64);

      // Send the ARP replay back to the input port
      struct ofl_action_output *action =
        (struct ofl_action_output*)xmalloc (sizeof (struct ofl_action_output));
      action->header.type = OFPAT_OUTPUT;
      action->port = OFPP_IN_PORT;
      action->max_len = 0;

      // Send the ARP reply within an OpenFlow PacketOut message
      struct ofl_msg_packet_out reply;
      reply.header.type = OFPT_PACKET_OUT;
      reply.buffer_id = OFP_NO_BUFFER;
      reply.in_port = inPort;
      reply.data_length = 64;
      reply.data = &replyData[0];
      reply.actions_num = 1;
      reply.actions = (struct ofl_action_header**)&action;

      SendToSwitch (swtch, (struct ofl_msg_header*)&reply, xid);
      free (action);
    }

  // All handlers must free the message when everything is ok
  ofl_msg_free ((struct ofl_msg_header*)msg, 0);
  return 0;
}

void
OFSwitch13DagController::SetMinNSwitches (uint16_t count)
{
  NS_LOG_FUNCTION (this << count);
  m_numSwitches = count;
}

void
OFSwitch13DagController::SetDemands (std::map<std::pair<uint16_t,uint16_t>,double> demands)
{
  NS_LOG_FUNCTION (this);

  uint32_t label = 16;
  for (auto& d : demands)
    {
      m_demands.insert ({d.first, {d.second, Linklist(), std::vector<std::list<uint16_t>>(), label++}});
    }
}

void
OFSwitch13DagController::UpdateTopology (void)
{
  NS_LOG_FUNCTION (this);

  Ptr<OFSwitch13Device> device;
  Ptr<OFSwitch13Port> port;
  Ptr<NetDevice> netdev;
  Ptr<CsmaChannel> channel;
  uint32_t count;
  std::map<Ptr<NetDevice>,uint64_t> netDevToDP;  // cache NetDevice -> dpId info

  for (auto& x : m_topology)
    {
      // clear the list of current neighbors
      x.second.clear ();

      device = OFSwitch13Device::GetDevice (x.first);
      NS_ASSERT_MSG (device != 0, "Device not found");

      for (uint32_t i = 1; i <= device->GetNSwitchPorts (); i++)
        {
          port = device->GetOFSwitch13Port (i);
          NS_ASSERT_MSG (port != 0, "Port not found");
          netdev = port->GetNetDevice ();
          NS_ASSERT_MSG (netdev != 0, "NetDevice not found");

          Neighbor nb;
          nb.m_portNo = i;
          nb.m_localDev = netdev;
          netDevToDP.insert ({netdev, x.first});

          channel = DynamicCast<CsmaChannel> (netdev->GetChannel ());
          NS_ASSERT_MSG (channel != 0, "CSMA Channel not found");
          count = channel->GetNDevices ();
          NS_ASSERT_MSG (count == 2, "Only links with two attached devices are supported");
          if (channel->GetDevice (0) != netdev)
            {
              netdev = channel->GetDevice (0);
            }
          else
            {
              NS_ASSERT_MSG (channel->GetDevice (1) != netdev, "Netdevice attached twice to the channel");
              netdev = channel->GetDevice (1);
            }
          nb.m_remoteDev = netdev;
          nb.m_capacity = channel->GetDataRate ();
          nb.m_flow = 0;

          x.second.push_back (nb);
        }
    }

  // Clear the list of edge switches
  m_edges.clear ();

  // Complete the missing dpId field by using the cached info
  for (auto& x : m_topology)
    {
      NS_LOG_DEBUG ("Neighbors for datapath " << x.first);

      for (auto nb = x.second.begin (); nb != x.second.end (); )
        {
          auto search = netDevToDP.find (nb->m_remoteDev);
          if (search == netDevToDP.end ())
            {
              NS_LOG_DEBUG ("Neighbor with no dpId, likely a host. Removing.");

              if (m_edges.find (x.first) != m_edges.end ())
                {
                  NS_LOG_DEBUG ("Switch " << x.first << " already in the list of edge switches");
                }
              else
                {
                  NS_LOG_DEBUG ("Adding switch " << x.first << " to the list of edge switches");
                  Ptr<Node> node = nb->m_remoteDev->GetNode ();
                  NS_ASSERT (node != 0);
                  Ptr<Ipv4> ipv4 = node->GetObject<Ipv4> ();
                  NS_ASSERT (ipv4 != 0);
                  int32_t iface = ipv4->GetInterfaceForDevice (nb->m_remoteDev);
                  NS_ASSERT (iface != -1);
                  Ipv4Address ipAddress = ipv4->GetAddress (iface, 0).GetLocal ();
                  Mac48Address macAddress = Mac48Address::ConvertFrom (nb->m_remoteDev->GetAddress ());
                  m_edges.insert ({x.first, {nb->m_portNo, ipAddress, macAddress}});
                }
              auto tmp = nb++;
              x.second.erase (tmp);
            }
          else
            {
              nb->m_dpId = search->second;
              NS_LOG_DEBUG ("dpId " << nb->m_dpId << " (bw " << nb->m_capacity << ")");
              nb++;
            }
        }
    }
}


/********** Private methods **********/
void
OFSwitch13DagController::HandshakeSuccessful (
  Ptr<const RemoteSwitch> swtch)
{
  NS_LOG_FUNCTION (this << swtch);

  // After a successfull handshake, let's install the table-miss entry, setting
  // to 128 bytes the maximum amount of data from a packet that should be sent
  // to the controller.
  DpctlExecute (swtch, "flow-mod cmd=add,table=0,prio=0 "
                "apply:output=ctrl:128");

  // Configure te switch to buffer packets and send only the first 128 bytes of
  // each packet sent to the controller when not using an output action to the
  // OFPP_CONTROLLER logical port.
  DpctlExecute (swtch, "set-config miss=128");

  // Create an empty NeighborList and insert it into m_topology
  NeighborList nbList;
  uint64_t dpId = swtch->GetDpId ();

  std::pair <Topology::iterator, bool> res;
  res =  m_topology.insert (std::pair<uint64_t, NeighborList> (dpId, nbList));
  if (res.second == false)
    {
      NS_LOG_ERROR ("NeighborList exists for this datapath.");
    }

  // Update the topology if at least m_numSwitches are connected
  if (m_topology.size () >= m_numSwitches)
    {
      UpdateTopology ();

      m_Bucket.resize (m_topology.size ());

      // compute DAGs
      for (auto& d : m_demands)
        {
          NS_LOG_DEBUG ("Computing DAG for demand (" << d.first.first << "," << d.first.second << ")");
          FindLooplessResilientDAG (d.first.first, d.first.second);
        }

      // route demands over the computed DAGs
          double maxu = MinimizeMaxUtilization ();
          MaximizeMinFlow (maxu);

      // install flow entries and group entries
      InstallEntries ();
      
      if (m_period)
        {
          Simulator::Schedule (Seconds (m_period),
                               &OFSwitch13DagController::UpdateNeighborsToBinsAssignment, this);
        }
    }
}


/* Helper function to add a BasePath to a DAG */
static void
addPathToDAG (DAG& dag, BasePath* path)
{
  std::set<std::pair<int,int> > tmp;

  for (int ver=1; ver < path->length(); ver++)
    tmp.insert(std::pair<int,int>(path->GetVertex(ver-1)->getID(),path->GetVertex(ver)->getID()));

  dag.addLinks(tmp);
}


/* Returns the set of links to initialize the DAG to */
std::set<std::pair<int,int>>
InitialLinkSet (const AdjLists& adj, std::pair<int,int> p)
{
  SubGraph graph (adj);
  std::set<std::pair<int,int>> ret;

  DijkstraShortestPathAlg dijkstra (&graph);

  BasePath* path = dijkstra.get_shortest_path (graph.get_vertex (p.first), graph.get_vertex (p.second));

  NS_LOG_DEBUG ("Found shortest path of length " << path->length() << " between " << p.first
                << " and " << p.second);

  for (int i = 1; i < path->length (); i++)
    {
      auto u = path->GetVertex (i-1)->getID ();
      auto v = path->GetVertex (i)->getID ();
      NS_LOG_DEBUG ("Inserting link " << u << "->" << v);
      ret.insert ({u, v});
      NS_ASSERT (std::find (adj[u].cbegin (), adj[u].cend (), v) != adj[u].cend ());
    }

  delete path;
  return ret;
}


void
OFSwitch13DagController::FindLooplessResilientDAG (uint16_t s, uint16_t d)
{
  NS_LOG_FUNCTION (this << s << d);

  // convert Topology to AdjLists
  AdjLists adj (m_topology.size ());

  for (auto& u : m_topology)
    {
      for (auto& v : u.second)
        {
          adj.at (u.first-1).push_back (v.m_dpId-1);      // datapath IDs start at 1
        }
    }

  SubGraph my_graph(adj);

  BasePath* path;
  bool found;
  int Lsu, Lud;

  // create a DAG
  DAG dag(adj.size());

  dag.addLinks (InitialLinkSet (adj, pair<int,int>(s,d)));

  // run a DFS to sort the nodes, find predecessors
  dag.DFS(s);

//   NS_LOG_DEBUG (dag);

  int minlen = dag.getMaxDistToDest(s);

  // a node is "done" when it is protected against single link/node failures
  vector<bool> done(adj.size(), false);

  /*
   * nodes are protected starting from the penultimate node in the topological ordering
   */ 

  list<int>::const_reverse_iterator u = ++dag.sorted_rbegin();
  set<int>::const_iterator v;

  while (u != dag.sorted_rend())
  {
//     NS_LOG_DEBUG ("Analyzing node " << *u << " Num adj: " << dag.getNumAdj(*u));

    // if u is done, continue with its predecessor
    if (done[*u])
    {
      u++;
      continue;
    }

    NS_ASSERT (dag.getNumAdj(*u)>0);

    // we check whether u is able to reach d despite the failure of each of its neighbors.
    // As soon as this is not true, an alternative path is sought and added to the dag; then,
    // the while loop starts again from the penultimate node
    // for (set<int>::const_iterator v=dag.adj_begin(*u); v!=dag.adj_end(*u); v++) {
    if (dag.getNumAdj(*u) == 1)
    {
      // copy the current dag and prune the neighbor
      // DAG pruned_dag(dag);

      v = dag.adj_begin(*u);

/*      if (*v == d)
	pruned_dag.removeLink(*u,d);
      else
	pruned_dag.removeNode(*v);*/

      // check whether a path still exists in pruned_dag between u and d
      // this can be done by running DFS and checking whether d has a valid predecessor
      // pruned_dag.DFS(*u);

      // if a path is not found
      // if (pruned_dag.getPred(d) == pruned_dag.getNumNodes()) {
	// we try to find an alternative path in the graph
	SubGraph pruned_graph(my_graph);

	if (*v == d)
	{
	  pruned_graph.removeEdge(*u,d);
// 	  NS_LOG_DEBUG ("prune link " << *u << "->" << d);
	}
	else
	{
	  pruned_graph.removeVertex(*v);
// 	  NS_LOG_DEBUG ("prune node " << *v);
	}

	YenTopKShortestPathsAlg yen(pruned_graph, pruned_graph.get_vertex(*u), pruned_graph.get_vertex(d));

//	cout << (yen.has_next() ? "true" : "false") << endl;

	found = false;
	Lsu = dag.getMaxDistFromSource(*u);
	Lud = 0;

//     NS_LOG_DEBUG ("Lsu = " << Lsu);

	while(yen.has_next() && !found && (Lsu + Lud <= m_alpha * minlen) )
	{
		path = yen.next();

// 		NS_LOG_DEBUG ("Trying path... " << path);

		// try to add path to the dag and check for loops and maximum length
		DAG augm_dag(dag);

		addPathToDAG(augm_dag, path);
		
		augm_dag.DFS(s);

		if (augm_dag.isAcyclic() && augm_dag.getMaxDistToDest(s) <= m_alpha * minlen)
        {
		  found = true;
// 		  NS_LOG_DEBUG ("Path is OK");
		}
		else if (!augm_dag.isAcyclic())
        {
// 		  NS_LOG_DEBUG ("Loop in the DAG");
        }
		else
        {
// 		  NS_LOG_DEBUG ("Path is too long!");
        }

		Lud = path->length() - 1;

// 		NS_LOG_DEBUG ("Lud = " << Lud);
	}

	if (found)
	{
	  done[*u] = true;

	  // add the path to the DAG
	  addPathToDAG(dag, path);

	  // sort the nodes in the new dag
	  dag.DFS(s);

	  // restart from the penultimate node
	  u = ++dag.sorted_rbegin();

//       NS_LOG_DEBUG (dag);

      delete path;
	  continue;
	}
      //}
    }

    done[*u] = true;
    u++;

//     NS_LOG_DEBUG (dag);
  }

    NS_LOG_DEBUG (dag);

  for (list<int>::const_iterator p=dag.sorted_begin(); p!=dag.sorted_end(); p++)
    for (set<int>::const_iterator q=dag.adj_begin(*p); q!=dag.adj_end(*p); q++)
      m_demands.at (std::pair<uint16_t,uint16_t>(s,d)).m_linkList.push_back ({*p,*q});
}

double
OFSwitch13DagController::MinimizeMaxUtilization (void)
{
  CoinBuild buildObject;
  int Ncol;

  { /* CONSTRAINT 1 */
    // To iterate once over all the DAGs to write constraints 1 (M is the max utilization)
    // we keep the coefficients and column numbers for each link in distinct vectors
    std::map<std::pair<uint16_t,uint16_t>, std::vector<int> > colno_m;
    std::map<std::pair<uint16_t,uint16_t>, std::vector<double> > coeff_m;
    
    int i = 0;  // column index

    for (auto& dem : m_demands)
      {
        for (auto& l : dem.second.m_linkList)
          {
            colno_m[l].push_back (i);
            coeff_m[l].push_back (-1.);

            i++;
          }
      } // i is the index of M

    Ncol = i+1;

    // add all the constraints link by link
    auto colno = colno_m.begin ();
    auto coeff = coeff_m.begin ();

    for ( ; colno != colno_m.end (); colno++, coeff++)
      {
        // find the capacity of the link
        auto link = colno->first;
        auto neighb = m_topology[link.first + 1].begin ();
        while (neighb != m_topology[link.first + 1].end ()
               && neighb->m_dpId != static_cast<uint16_t>(link.second + 1))
          {
            neighb++;
          }
        if (neighb == m_topology[link.first + 1].end ())
          {
            NS_FATAL_ERROR (link.second << " is not a neighbor of " << link.first);
          }

        // add the coefficient for M
        colno->second.push_back (Ncol-1);
        coeff->second.push_back (neighb->m_capacity.GetBitRate ());

        buildObject.addRow (colno->second.size (), colno->second.data (), coeff->second.data (),
                            0., COIN_DBL_MAX);
      }
  }

  { /* CONSTRAINT 2 */
    int i = 0;  // column index

    for (auto& dem : m_demands)
      {
        // we keep the coefficients and column numbers for each node of the DAG in distinct vectors
        std::map<uint16_t, std::vector<int> > colno_m;
        std::map<uint16_t, std::vector<double> > coeff_m;

        for (auto& l : dem.second.m_linkList)
          {
            colno_m[l.first].push_back (i);
            coeff_m[l.first].push_back (1.);

            colno_m[l.second].push_back (i);
            coeff_m[l.second].push_back (-1.);

            i++;
          }

        // add the constraints for this demand
        auto colno = colno_m.begin ();
        auto coeff = coeff_m.begin ();

        for ( ; colno != colno_m.end (); colno++, coeff++)
          {
            double limit = 0.;

            if (colno->first == dem.first.first)
              {
                limit = dem.second.m_bwd;
              }
            else if (colno->first == dem.first.second)
              {
                limit = -dem.second.m_bwd;
              }

            buildObject.addRow (colno->second.size (), colno->second.data (), coeff->second.data (),
                                limit, limit);
          }
      }
  }

  ClpSimplex model;

  model.resize (0, Ncol);
  model.setObjectiveCoefficient (Ncol-1, 1);
  model.setOptimizationDirection (1);  // minimize
  model.addRows(buildObject);

  if (model.initialSolve ())
    {
      NS_FATAL_ERROR ("Could not solve the LP!");
    }

  double maxu = model.objectiveValue ();

  std::cout << "************ Max link utilization : " << maxu << " ****************" << std::endl;

  return maxu;
}


void
OFSwitch13DagController::MaximizeMinFlow (double maxUtil)
{
  CoinBuild buildObject;
  int Ncol;

  { /* CONSTRAINT 1 */
    // To iterate once over all the DAGs to write constraints 1
    // we keep the coefficients and column numbers for each link in distinct vectors
    std::map<std::pair<uint16_t,uint16_t>, std::vector<int> > colno_m;
    std::map<std::pair<uint16_t,uint16_t>, std::vector<double> > coeff_m;

    int i = 0;  // column index

    for (auto& dem : m_demands)
      {
        for (auto& l : dem.second.m_linkList)
          {
            colno_m[l].push_back (i);
            coeff_m[l].push_back (1.);

            i++;
          }
      } // i is the index of M

//     Ncol = i+1;
    Ncol = i;

    // add all the constraints link by link
    auto colno = colno_m.begin ();
    auto coeff = coeff_m.begin ();

    for ( ; colno != colno_m.end (); colno++, coeff++)
      {
        // find the capacity of the link
        auto link = colno->first;
        auto neighb = m_topology[link.first + 1].begin ();
        while (neighb != m_topology[link.first + 1].end ()
               && neighb->m_dpId != static_cast<uint16_t>(link.second + 1))
          {
            neighb++;
          }
        if (neighb == m_topology[link.first + 1].end ())
          {
            NS_FATAL_ERROR (link.second << " is not a neighbor of " << link.first);
          }

        buildObject.addRow (colno->second.size (), colno->second.data (), coeff->second.data (),
                            0., neighb->m_capacity.GetBitRate () * (maxUtil+0.01));
      }
  }

  { /* CONSTRAINT 2 */
    int i = 0;  // column index

    for (auto& dem : m_demands)
      {
        // we keep the coefficients and column numbers for each node of the DAG in distinct vectors
        std::map<uint16_t, std::vector<int> > colno_m;
        std::map<uint16_t, std::vector<double> > coeff_m;

        for (auto& l : dem.second.m_linkList)
          {
            colno_m[l.first].push_back (i);
            coeff_m[l.first].push_back (1.);

            colno_m[l.second].push_back (i);
            coeff_m[l.second].push_back (-1.);

            i++;
          }

        // add the constraints for this demand
        auto colno = colno_m.begin ();
        auto coeff = coeff_m.begin ();

        for ( ; colno != colno_m.end (); colno++, coeff++)
          {
            double limit = 0.;

            if (colno->first == dem.first.first)
              {
                limit = dem.second.m_bwd;
              }
            else if (colno->first == dem.first.second)
              {
                limit = -dem.second.m_bwd;
              }

            buildObject.addRow (colno->second.size (), colno->second.data (), coeff->second.data (),
                                limit, limit);
          }
      }
  }

  { /* CONSTRAINT 3 */
    int colno[2];
    double coeff[2];

    int i = 0,  // column index
        j = 0;  // demand index

    for (auto& dem : m_demands)
      {
        for (auto& l : dem.second.m_linkList)
          {
            NS_UNUSED (l);
            colno[0] = i;
            coeff[0] = 1.;

//             colno[1] = Ncol-1;
            colno[1] = Ncol+j;
            coeff[1] = -dem.second.m_bwd;

            buildObject.addRow (2, colno, coeff, 0., COIN_DBL_MAX);

            i++;
          }
        j++;
      } // i is the index of M
  }

  ClpSimplex model;

//   model.resize (0, Ncol);
  model.resize (0, Ncol+m_demands.size ());
//   model.setObjectiveCoefficient (Ncol-1, 1);
  for (std::size_t j = 0; j < m_demands.size (); j++)
    {
      model.setObjectiveCoefficient (Ncol+j, 1);
    }
  model.setOptimizationDirection (-1);  // maximize
  model.addRows(buildObject);
//   for (int i = 0; i < Ncol; i++)
//     {
//       model.setColumnLower (i, 0.);
//     }

  if (model.initialSolve ())
    {
      NS_FATAL_ERROR ("Could not solve the LP!");
    }

  NS_LOG_DEBUG ("Obj value: " << model.objectiveValue ());

  double* res = model.primalColumnSolution();

  std::stringstream ss;
  std::copy (res+Ncol, res+Ncol+m_demands.size (), std::ostream_iterator<double> (ss, " "));
  NS_LOG_DEBUG ("Min (normalized) flow per demand: " << ss.str ());

  int i = 0;
  m_ptrVar.clear ();
  for (auto& dem : m_demands)
    {
      NS_LOG_DEBUG ("Demand " << dem.first.first << "->" << dem.first.second << "  " << dem.second.m_bwd);

      for (auto& l : dem.second.m_linkList)
        {
          m_ptrVar[dem.first].push_back (res[i++]);
          NS_LOG_DEBUG ("Link " << l.first << "->" << l.second << "   " << m_ptrVar[dem.first].back ());
        }
    }
}


double
OFSwitch13DagController::InverseBwd (uint16_t u, uint16_t v)
{
  for (auto& n : m_topology[u+1])
    {
      if ((uint16_t)n.m_dpId == v+1)
        {
          if (n.m_capacity.GetBitRate () <= n.m_flow.GetBitRate ())
            {
              NS_FATAL_ERROR ("Link " << u << "->" << v << " has not enough available bandwidth");
            }

          return 1. / (n.m_capacity.GetBitRate () - n.m_flow.GetBitRate ());
        }
    }
  NS_FATAL_ERROR ("Link " << u << "->" << v << " not found");
}


void
OFSwitch13DagController::InstallEntries (void)
{
  NS_LOG_FUNCTION (this);

  // For every switch
  for (auto& u : m_topology)
    {
      NS_LOG_DEBUG ("Installing entries on switch " << u.first-1);

      uint16_t groupID = 1;
      uint16_t flowcount = 0;

      // Install as many group entries as the number of neighbor pairs.
      // Each group entry forwards the packet to the first live port
      for (auto& v : u.second)
        {
          for (auto& w : u.second)
            {
              if (v.m_dpId == w.m_dpId)
                {
                  // install a group entry of indirect type (useful in case there is a
                  // single neighbor in the DAG)
                  // <group ID = 1,2,...> <Group Type = indirect> <Bucket: Output = port>
                  std::ostringstream cmd;
                  cmd << "group-mod cmd=add,type=ff,group=" << groupID++
                      << " weight=0,port=" << v.m_portNo << ",group=any output=" << v.m_portNo;
                  DpctlExecute (u.first, cmd.str ());
                  NS_LOG_DEBUG ("Installed group entry <" << cmd.str() << ">");
                }
              else
                {
                  // <group ID = 1,2,...> <Group Type = fast_failover> <Bucket_1: Output = port>  <Bucket_2: Output = port>
                  std::ostringstream cmd;
                  cmd << "group-mod cmd=add,type=ff,group=" << groupID++
                      << " weight=0,port=" << v.m_portNo << ",group=any output=" << v.m_portNo
                      << " weight=0,port=" << w.m_portNo << ",group=any output=" << w.m_portNo;
                  DpctlExecute (u.first, cmd.str ());
                  NS_LOG_DEBUG ("Installed group entry <" << cmd.str() << ">");
                }
            }
        }

      // For every demand
      for (auto& d : m_demands)
        {
          NS_LOG_DEBUG ("* Demand (" << d.first.first << "," << d.first.second << ") *");

          // If this switch is the destination node for this demand, install a flow
          // entry removing the MPLS label and a group entry to deliver the packet to the host
          if (d.first.second == u.first-1)
            {
              std::ostringstream cmd;
              cmd << "group-mod cmd=add,type=ind,group=" << groupID
                  << " weight=0,port=any,group=any output=" << m_edges.at (u.first).m_portNo;
              DpctlExecute (u.first, cmd.str ());
              NS_LOG_DEBUG ("Installed group entry <" << cmd.str() << ">");

              std::ostringstream cmdi;
              cmdi << "flow-mod cmd=add,table=0,prio=100"
                   << " eth_type=0x8847,mpls_label=" << d.second.m_label
                   << " apply:pop_mpls=0x0800,group=" << groupID++;
              DpctlExecute (u.first, cmdi.str ());
              NS_LOG_DEBUG ("Installed flow entry <" << cmdi.str() << ">");
              flowcount++;
              continue;
            }

          std::vector<uint16_t> bucket = ComputeBinsLP (u.first-1, d.first);

          // if the bucket is empty, no path for this demand traverses this node, so
          // continue with the next demand
          if (bucket.empty ())
            {
              continue;
            }

          // Otherwise, install one group entry per demand, which includes nBins buckets
          // pointing to the group entries installed above.
          // <group ID> <Group Type = select> <Bucket_1: Group = id_1> ... <Bucket_nBins: Group = id_nBins>
          std::ostringstream cmd;
          cmd << "group-mod cmd=add,type=sel,group=" << groupID;
          for (auto& bin : bucket)
            {
              cmd << " weight=1,port=any,group=any group=" << bin << ",set_field=mpls_label:" << d.second.m_label;
            }
          DpctlExecute (u.first, cmd.str ());
          NS_LOG_DEBUG ("Installed group entry <" << cmd.str() << ">");

          // store the groupID in the map
          m_groupIDs[std::make_pair (u.first,d.first)] = groupID;

          // store the bucket in m_Bucket
          m_Bucket.at (u.first-1).emplace (d.first, std::move (bucket));

          // Install one flow entry pointing to the group entry just added for this demand
          if (d.first.first == u.first-1)
            {
              // This node is the source of the demand
              std::ostringstream cmdi;
              cmdi << "flow-mod cmd=add,table=0,prio=100"
                   << " eth_type=0x0800,ip_dst=" << m_edges.at (d.first.second+1).m_ipAddress
                   << " apply:push_mpls=0x8847,group=" << groupID++;
              DpctlExecute (u.first, cmdi.str ());
              NS_LOG_DEBUG ("Installed flow entry <" << cmdi.str() << ">");
            }
          else
            {
              std::ostringstream cmdi;
              cmdi << "flow-mod cmd=add,table=0,prio=100"
                   << " eth_type=0x8847,mpls_label=" << d.second.m_label
                   << " apply:group=" << groupID++;
              DpctlExecute (u.first, cmdi.str ());
              NS_LOG_DEBUG ("Installed flow entry <" << cmdi.str() << ">");
            }
          flowcount++;
        }
      std::cout << "LPNode " << u.first-1 << " flow " << flowcount << " group " << groupID << std::endl;
    }

  /* We don't need m_ptrVar anymore */
//   m_ptrVar.clear ();
}

std::vector<uint16_t>
OFSwitch13DagController::ComputeBins (uint16_t node, std::pair<uint16_t,uint16_t> d)
{
  std::vector<uint16_t> bucket (m_nBins, 0);
  std::vector<uint16_t> groupIDs;
  std::set<uint16_t> neighb;

  // check which paths for this demand traverse this switch
  for (auto p = m_demands.at (d).m_paths.begin(); p != m_demands.at (d).m_paths.end(); p++)
    {
      auto pos = std::find (p->begin (), p->end (), node);

      if (pos != p->end())
        {
          uint16_t nb = *(++pos);
          // find the neighbor in struct Neighbor
          bool found = false;
          for (auto v = m_topology.at (node+1).begin(); v != m_topology.at (node+1).end(); v++)
            {
              if ((uint16_t)v->m_dpId == nb+1)
                {
                  bucket.at (std::distance (m_demands.at (d).m_paths.begin(), p)) = std::distance (m_topology.at (node+1).begin(), v) + 1; 
                  neighb.insert (std::distance (m_topology.at (node+1).begin(), v) + 1);
                  found = true;
                }
            }
          if (!found)
            {
              NS_FATAL_ERROR ("Next hop in the path not found among the neighbors");
            }
        }
    }

  if (m_demands.at (d).m_paths.empty ())
    {
      std::cout << "*** No paths available for demand (" << d.first << "," << d.second << ")" << std::endl;
    }

  // If neighb is empty, it means no path for this demand traverses this node
  if (neighb.empty ())
    {
      return std::vector<uint16_t>();
    }

  // A node with multiple neighbors is something to print out
  if (neighb.size () > 1)
    {
      std::cout << "Demand (" << d.first << "," << d.second << "): Node " << node
                << " has multiple neighbors: ";
      for (auto& i : neighb)
        {
          std::cout << std::next (m_topology.at (node+1).begin (), i-1)->m_dpId - 1 << " ";
        }
      std::cout << std::endl;
    }

  // Fill the remaining cells in a round robin fashion
  std::set<uint16_t>::iterator n = neighb.begin ();

  for (auto& bin : bucket)
    {
      if (!bin)
        {
          bin = (++n != neighb.end () ? *n : *(n = neighb.begin ()));
        }

      // find the position of bin within neighb
      auto nb = neighb.find (bin);
      // the backup neighbor is the next one in neighb
      auto bak = (++nb != neighb.end () ? *nb : *(nb = neighb.begin ()));

      // Compute the groupIDs assuming that fast failover groups are installed this way:
      // groupID  type  active  backup
      //    1      ff      A
      //    2      ff      A       B
      //    3      ff      A       C
      //    4      ff      A       D
      //    5      ff      B       A
      //    6      ff      B
      //    ...
      // where A, B, C, D are the neighbors of this node (in the same order
      // as they appear in m_topology[node]

     // bin and bak start at 1 (group IDs as well)
      groupIDs.push_back ((bin-1)*(m_topology.at (node+1).size()) + bak);
    }

  return groupIDs;
}

/*
 * Replaces the elements of 'result' that are equal to 'toReplace' with the keys of
 * 'target' so that the sum of the load shares over all the bins assigned to the
 * neighbor approximates the corresponding values in the 'target' map
 */
void
ComputeTarget (std::vector<double> binShare, std::map<uint16_t,double>& target, std::vector<uint16_t>& result, uint16_t toReplace)
{
  NS_ASSERT (binShare.size () == result.size ());

  std::map<uint16_t,double> load;   // bin load shares

  for (auto& m : target)
    {
      load.insert ({m.first,0.});
    }

  uint16_t i = 0;

  for (auto& val : result)
    {
      // if the value is to be replaced, compute the most suitable value
      if (val == toReplace)
        {
          std::map<uint16_t,double> dist;
          // evaluate what if each of the keys is selected
          for (auto& m : target)
            {
              load.at (m.first) += binShare.at (i);
              
              double diff = 0;
              auto ci = load.begin (), ti = target.begin ();
              for ( ; ci != load.end (); ci++, ti++)
                {
                  diff += (ci->second - ti->second)*(ci->second - ti->second);
                }

              dist[m.first] = diff;
              load.at (m.first) -= binShare.at (i);
            }
          // find the minimum distance
          auto best = std::min_element (dist.begin(), dist.end(),
                                        [](const std::pair<uint16_t,double> &left, const std::pair<uint16_t,double> &right)
                                        {
                                          return left.second < right.second;
                                        });

          val = best->first;
        }
      // update the load map
      load.at (val) += binShare.at (i++);
    }
}


std::vector<uint16_t>
OFSwitch13DagController::ComputeBinsLP (uint16_t node, std::pair<uint16_t,uint16_t> d)
{
  NS_LOG_FUNCTION (this << node << d.first << d.second);

  // maps neighbor position (in NeighborList) to split ratio
  std::map<uint16_t,double> split_ratios;
  double incomingFlow = 0.;

  NS_ASSERT_MSG (node != d.second, "No bins are to be computed for the egress node");

  // compute incoming flow and the flow outgoing toward each neighbor
  int i = 0;
  for (auto& l : m_demands.at (d).m_linkList)
    {
      if (l.second == node)
        {
          incomingFlow += m_ptrVar.at (d).at (i);
        }
      else if (l.first == node)
        {
          // find the neighbor in struct Neighbor
          uint16_t pos = 0;
          for (auto& v : m_topology.at (node+1))
            {
              if ((uint16_t)v.m_dpId == l.second+1)
                {
                  if (split_ratios.find (pos) == split_ratios.end ())
                    {
                      split_ratios[pos] = m_ptrVar.at (d).at (i);
                    }
                  else
                    {
                      split_ratios.at (pos) += m_ptrVar.at (d).at (i);
                    }
                  break;
                }
              else
                {
                  pos++;
                }
            }
          if (pos == m_topology.at (node+1).size ())
            {
              NS_FATAL_ERROR ("Link end point not found among the neighbors");
            }
        }
      i++;
    }

  if (node == d.first)
    {
      incomingFlow = m_demands. at(d).m_bwd;
    }

  // If the incoming flow is null, it means this demand does not traverse this node
  if (!incomingFlow)
    {
      return std::vector<uint16_t>();
    }

  // normalize split_ratios to incoming flow and remove null split ratios
  std::stringstream ratios;
  for (auto r = split_ratios.begin (); r != split_ratios.end (); )
    {
      r->second /= incomingFlow;
      // if the split ratio is too small, remove it. Null split ratios are dangerous
      // because (especially in case of failures) may be used to send packets to
      // neighbors where flow rules for this demand have not been installed
      if (r->second < 0.001)
        {
          auto tmp = std::next (r);
          split_ratios.erase (r);
          r = tmp;
        }
      else
        {
          ratios << r->second << " ";
          r++;
        }
    }

  // We may arrive here if the incoming flow is very small
  if (split_ratios.empty ())
    {
      return std::vector<uint16_t>();
    }

  NS_LOG_DEBUG ("Demand (" << d.first << "," << d.second << "): Node " << node
                << " has these split ratios: " << ratios.str ());

  // initialize the active bucket (with invalid values)
  std::vector<uint16_t> bucketA (m_nBins, m_topology.at (node+1).size ());
#if 0
  // set the first values to the neighbors with non null split ratio
  NS_ASSERT (m_nBins >= split_ratios.size ());
  i = 0;
  for (auto& r : split_ratios)
    {
      bucketA.at (i++) = r.first;
    }
#endif
  // assume the load is uniformly distributed among bins
  std::vector<double> binShares (bucketA.size (), 1./bucketA.size ());

  auto gID = m_groupIDs.find (std::make_pair (node+1,d));

  // if we are not at init, compute the actual load shares of the bins
  if (gID != m_groupIDs.end ())
    {
      struct group_table* gtable = OFSwitch13Device::GetDevice (node+1)->GetDatapath ()->groups;

      struct group_entry* gentry = group_table_find (gtable, gID->second);
      
      NS_ASSERT (gentry);

      if (gentry->stats->byte_count == 0)
        {
          // no traffic, don't update anything
          return std::vector<uint16_t>();
        }

      NS_LOG_DEBUG ("Retrieving load");
      for (size_t j = 0; j < gentry->stats->counters_num; j++)
        {
          binShares.at (j) = (double)(gentry->stats->counters[j]->byte_count)/gentry->stats->byte_count;
          // reset bucket counter
          gentry->stats->counters[j]->byte_count = 0;
          gentry->stats->counters[j]->packet_count = 0;
        }
      // reset group entry counter
      gentry->stats->byte_count = 0;
      gentry->stats->packet_count = 0;

//       std::copy (binShares.begin (), binShares.end (), std::ostream_iterator<double> (std::cout, " "));
//       std::cout << std::endl;
    }
  
  ComputeTarget (binShares, split_ratios, bucketA, m_topology.at (node+1).size ());

  // A node with multiple neighbors is something to print out
  if (split_ratios.size () > 1)
    {
//       std::cout << "Demand (" << d.first << "," << d.second << "): Node " << node
//                 << " has multiple neighbors: ";
//       for (auto& r : split_ratios)
//         {
//           std::cout << std::next (m_topology.at (node+1).begin (), r.first)->m_dpId - 1 << " ";
//         }
//       std::cout << std::endl;
    }

  std::stringstream ab;
  std::copy (bucketA.begin (), bucketA.end (), std::ostream_iterator<uint16_t> (ab, " "));
  NS_LOG_DEBUG ("Active Bucket : " << ab.str ());

  /* compute the backup bucket */

  std::vector<uint16_t> bucketB (bucketA);

  // if there is only one neighbor, the backup bucket is the same as the active one
  if (split_ratios.size () > 1)
    {
      for (auto& r : split_ratios)
        {
          // copy the split_ratios map
          std::map<uint16_t,double> split_ratios_bak (split_ratios);

          // erase one neighbor
          split_ratios_bak.erase (r.first);

          // calculate the sum of the remaining split ratios
          double sum = std::accumulate (split_ratios_bak.begin (), split_ratios_bak.end (), 0.,
                                            [](const double &partial, const std::pair<uint16_t,double> &elem)
                                            {
                                              return partial + elem.second;
                                            });

          // resize the split ratios
          for (auto& rb : split_ratios_bak)
            {
              rb.second /= sum;
            }

          // copy active bucket
          std::vector<uint16_t> bucketCopy (bucketA);
          std::vector<uint16_t> mask (m_nBins, 0);

          // compute the mask of the positions of the neighbor to protect
          for (std::size_t b = 0; b < bucketCopy.size (); b++)
            {
              if (bucketCopy[b] == r.first)
                {
                  mask[b] = 1;
                }
            }

          // compute the bucket in case this neighbor fails e the traffic is partitioned among the others
          ComputeTarget (binShares, split_ratios_bak, bucketCopy, r.first);

          // save only the newly computed backup neighbors in bucketB
          for (std::size_t b = 0; b < bucketCopy.size (); b++)
            {
              if (mask[b] == 1)
                {
                  bucketB[b] = bucketCopy[b];
                }
            }
        }
    }
  
  std::stringstream bb;
  std::copy (bucketB.begin (), bucketB.end (), std::ostream_iterator<uint16_t> (bb, " "));
  NS_LOG_DEBUG ("Backup Bucket : " << bb.str ());

  std::vector<uint16_t> groupIDs;

  for (std::size_t b = 0; b < bucketA.size (); b++)
    {
     // bucket values start at 0 (group IDs at 1)
      groupIDs.push_back (bucketA[b]*(m_topology.at (node+1).size()) + bucketB[b] + 1);
    }

  return groupIDs;
}


void
OFSwitch13DagController::UpdateNeighborsToBinsAssignment (void)
{
    double maxu = MinimizeMaxUtilization ();
    MaximizeMinFlow (maxu);

  // For every switch
  for (auto& u : m_topology)
    {
      // For every demand
      for (auto& d : m_demands)
        {
          auto gID = m_groupIDs.find (std::make_pair (u.first,d.first));

          if (gID == m_groupIDs.end ())
            {
              continue;
            }

          std::vector<uint16_t> bucket = ComputeBinsLP (u.first-1, d.first);

          // if the bucket is empty, continue with the next group
          if (bucket.empty ())
            {
              continue;
            }

          // Otherwise, modify one group entry per demand, which includes nBins buckets
          // pointing to the group entries installed above.
          // <group ID> <Group Type = select> <Bucket_1: Group = id_1> ... <Bucket_nBins: Group = id_nBins>
          std::ostringstream cmd;
          cmd << "group-mod cmd=mod,type=sel,group=" << gID->second;
          for (auto& bin : bucket)
            {
              cmd << " weight=1,port=any,group=any group=" << bin << ",set_field=mpls_label:" << d.second.m_label;
            }
          DpctlExecute (u.first, cmd.str ());
          NS_LOG_DEBUG ("Modified group entry <" << cmd.str() << ">");
        }
    }

  // Reschedule
  if (m_period)
  {
    Simulator::Schedule (Seconds (m_period),
                         &OFSwitch13DagController::UpdateNeighborsToBinsAssignment, this);
  }

}

std::vector<uint16_t>
OFSwitch13DagController::GetActivePathForFlow (Ipv4Address srcIp, Ipv4Address dstIp,
                                              uint8_t protocol,
                                              uint16_t srcPort, uint16_t dstPort)
{
  uint64_t srcDpId = 0, dstDpId = 0;

  // find the src and dst hosts in the data structure
  for (auto& host : m_edges)
    {
      if (host.second.m_ipAddress == srcIp)
        {
          srcDpId = host.first;
        }
      else if (host.second.m_ipAddress == dstIp)
        {
          dstDpId = host.first;
        }
    }
  NS_ASSERT_MSG (srcDpId && dstDpId, "Hosts not found!");

  auto dem = m_demands.find ({srcDpId-1, dstDpId-1});

  NS_ASSERT_MSG (dem != m_demands.end (), "Demand not found!");

  uint16_t node = srcDpId-1;
  std::vector<uint16_t> path {node};

  while (node != dstDpId-1)
    {
      uint8_t buf[12];
      srcIp.Serialize (buf);
      dstIp.Serialize (buf + 4);
      buf[8] = (srcPort >> 8) & 0xff;
      buf[9] = srcPort & 0xff;
      buf[10] = (dstPort >> 8) & 0xff;
      buf[11] = dstPort & 0xff;

      uint8_t bin = protocol;
      for (int i = 0; i < 12; i++)
        {
          bin = bin ^ buf[i];
        }

      // find the bucket
      auto bucket = m_Bucket.at (node).find (dem->first);
      NS_ASSERT_MSG (bucket != m_Bucket.at (node).end (), "Bucket not found!");

      bin = bin % bucket->second.size ();
      uint16_t neighbIndex = (bucket->second.at (bin) - 1) / m_topology.at (node+1).size();
      node = std::next (m_topology.at (node+1).begin (), neighbIndex)->m_dpId - 1;
      path.push_back (node);
    }

  return path;
}


} // namespace ns3

#endif // NS3_OFSWITCH13
