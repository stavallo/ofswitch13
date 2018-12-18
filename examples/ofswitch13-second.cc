/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014 University of Campinas (Unicamp)
 *
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
 *         Vitor M. Eichemberger <vitor.marge@gmail.com>
 *
 * Two hosts connected to a single OpenFlow switch.
 * The switch is managed by the default learning controller application.
 *
 *                       Learning Controller
 *                                |
 *                       +-----------------+
 *            Host 0 === | OpenFlow switch | === Host 1
 *                       +-----------------+
 */

#include <ns3/core-module.h>
#include <ns3/network-module.h>
#include <ns3/csma-module.h>
#include <ns3/internet-module.h>
#include <ns3/ofswitch13-module.h>
#include <ns3/internet-apps-module.h>
#include <ns3/applications-module.h>
#include "ns3/flow-monitor-module.h"
#include "ns3/traffic-control-module.h"
#include <map>
#include <vector>
#include <fstream>
#include <iomanip>
#include <ksp/DijkstraShortestPathAlg.h>

using namespace ns3;

struct Topology
{
  std::vector<std::string> m_nodes;                         //!< node names
  std::map<std::pair<uint16_t,uint16_t>,double> m_links;    //!< bidirectional links (u,v,capacity)
  std::map<std::pair<uint16_t,uint16_t>,double> m_demands;  //!< demands (s,d,bandwidth)
};

struct MyStats
{
  double m_load;          //!< Mbps
  double m_throughput;    //!< Mbps
  double m_delaySum;         //!< ms
  uint32_t m_rxPackets;
  uint32_t m_dropQD;
  uint32_t m_dropND;
};

class MeasureUtil
{
public:
  MeasureUtil (uint64_t capacity)
    : m_capacity (capacity), m_bitsSent (0) {}

  void RecvPacket (Ptr<const Packet> p)
    { m_bitsSent += p->GetSize () * 8; }

  void ResetInterval (void)
    {
      m_util.push_back (m_bitsSent * 1. / m_capacity);
      m_bitsSent = 0;
    }

  void Print (std::ostream& os) const
    {
      for (uint16_t u = 1; u < m_util.size (); u++)
        os << m_util[u] << std::endl;
    }
private:
  uint64_t m_capacity;
  uint64_t m_bitsSent;
  std::vector<double> m_util;
};

// prototypes
void ReadTopology (Topology& T, std::string topofile, std::string rateUnit, double factor, bool verbose);
void ReadDemands (Topology& T, std::string topofile, std::string rateUnit, double factor, bool verbose);
/*
 * Remove demands for which the hop count between edges is below minHops.
 * Ensure that demands are bidirectional (to send tcp acks)
 */
void FilterDemands (Topology& T, uint16_t minHops);
void ShuffleDemands (Topology& T, uint16_t shuffle);

int
main (int argc, char *argv[])
{
  bool verbose = false;
  bool trace = false;
  std::string topofile;
  std::string loadfile ("none");
  std::string loadfile2 ("none");
  std::string rateUnit = "Mbps";
  uint16_t minHops = 3;
  uint16_t numFlowsPerDemand = 30;
  uint32_t payloadSize = 1400;
  double onTime = 0.5, offTime = 0.1;
  double start = 5.0, duration = 10.0;
  double factor = 1.0;
  double warmup = 5.0;
  uint16_t bins = 10;
  uint16_t shuffle = 0;
  uint16_t shuffle2 = 0;

  // Configure command line parameters
  CommandLine cmd;
  cmd.AddValue ("simTime", "Simulation time (seconds)", duration);
  cmd.AddValue ("warmup", "Warmup time (seconds)", warmup);
  cmd.AddValue ("verbose", "Enable verbose output", verbose);
  cmd.AddValue ("trace", "Enable datapath stats and pcap traces", trace);
  cmd.AddValue ("topofile", "Topology file (from http://sndlib.zib.de)", topofile);
  cmd.AddValue ("load", "Read demands from another file (from http://sndlib.zib.de)", loadfile);
  cmd.AddValue ("load2", "Actually generated demands (from http://sndlib.zib.de)", loadfile2);
  cmd.AddValue ("shuffle", "Shuffle demands for controller", shuffle);
  cmd.AddValue ("shuffle2", "Shuffle demands before generating traffic", shuffle2);
  cmd.AddValue ("unit", "Data rate unit", rateUnit);
  cmd.AddValue ("hops", "Minimum number of hops to consider a demand", minHops);
  cmd.AddValue ("flows", "Number of flows per demand", numFlowsPerDemand);
  cmd.AddValue ("factor", "Multiplicative factor to apply to all demands", factor);
  cmd.AddValue ("bins", "Number of bins", bins);
  cmd.Parse (argc, argv);

  if (verbose)
    {
      OFSwitch13Helper::EnableDatapathLogs ();
      LogComponentEnable ("OFSwitch13Interface", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Device", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Port", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Queue", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13SocketHandler", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Controller", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13LearningController", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Helper", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13InternalHelper", LOG_LEVEL_ALL);
    }
//      LogComponentEnable ("OFSwitch13DagController", LOG_LEVEL_ALL);
//      LogComponentEnable ("OFSwitch13Port", LOG_LEVEL_ALL);

  // Enable checksum computations (required by OFSwitch13 module)
  GlobalValue::Bind ("ChecksumEnabled", BooleanValue (true));
  Config::SetDefault ("ns3::CsmaChannel::FullDuplex", BooleanValue (true));

  Topology T;
  ReadTopology (T, topofile, rateUnit, factor, true);
  if (loadfile != "none")
    {
      ReadDemands (T, loadfile, rateUnit, factor, true);
    }
  FilterDemands (T, minHops);
  if (shuffle)
    {
      ShuffleDemands (T, shuffle);
    }

  // Create as many host nodes as the number of switches
  NodeContainer hosts;
  hosts.Create (T.m_nodes.size ());

  // Create the switch nodes
  NodeContainer switches;
  switches.Create (T.m_nodes.size ());

  // Use the CsmaHelper to connect host nodes to the switch node
  CsmaHelper csmaHelper;
  csmaHelper.SetChannelAttribute ("DataRate", DataRateValue (DataRate ("10Gbps")));
  csmaHelper.SetChannelAttribute ("Delay", TimeValue (MilliSeconds (2)));

  NetDeviceContainer hostDevices;
  std::vector<NetDeviceContainer> switchPorts (T.m_nodes.size ());

  // Create links between a switch and a host
  for (uint16_t i = 0; i < T.m_nodes.size (); i++)
    {
      NodeContainer pair (hosts.Get (i), switches.Get (i));
      NetDeviceContainer link = csmaHelper.Install (pair);
      hostDevices.Add (link.Get (0));
      switchPorts[i].Add (link.Get (1));
    }

  std::vector<MeasureUtil*> linkUtil;
  MeasureUtil* mup;

  // Create links between switches
  for (auto& l : T.m_links)
    {
      NodeContainer pair (switches.Get (l.first.first), switches.Get (l.first.second));
      std::stringstream ss;
      ss << fixed << l.second << rateUnit;
      DataRate capacity (ss.str ());
      csmaHelper.SetChannelAttribute ("DataRate", DataRateValue (capacity));
      NetDeviceContainer link = csmaHelper.Install (pair);
      switchPorts[l.first.first].Add (link.Get (0));
      switchPorts[l.first.second].Add (link.Get (1));

      mup = new MeasureUtil (capacity.GetBitRate ());
      linkUtil.push_back (mup);
      link.Get (0)->TraceConnectWithoutContext ("PhyRxEnd",
                                                MakeCallback (&MeasureUtil::RecvPacket, mup));

      mup = new MeasureUtil (capacity.GetBitRate ());
      linkUtil.push_back (mup);
      link.Get (1)->TraceConnectWithoutContext ("PhyRxEnd",
                                                MakeCallback (&MeasureUtil::RecvPacket, mup));
    }

  // Create the controller node
  Ptr<Node> controllerNode = CreateObject<Node> ();

  // Configure the OpenFlow network domain
  Ptr<OFSwitch13InternalHelper> of13Helper = CreateObject<OFSwitch13InternalHelper> ();
  Ptr<OFSwitch13DagController> ctrl = CreateObjectWithAttributes<OFSwitch13DagController> ("NSwitches", UintegerValue (T.m_nodes.size ()), "NBins", UintegerValue (bins));
  ctrl->SetDemands (T.m_demands);
  of13Helper->InstallController (controllerNode, ctrl);
  for (uint16_t i = 0; i < T.m_nodes.size (); i++)
    {
      of13Helper->InstallSwitch (switches.Get (i), switchPorts[i]);
    }
  of13Helper->CreateOpenFlowChannels ();

  // Install the TCP/IP stack into hosts nodes
  InternetStackHelper internet;
  internet.Install (hosts);

  // Traffic control
  TrafficControlHelper tch;
  tch.SetRootQueueDisc ("ns3::FqCoDelQueueDisc");

  tch.Install (hostDevices);
  for (auto& s : switchPorts)
    {
      tch.Install (s);
    }

  // Set IPv4 host addresses
  Ipv4AddressHelper ipv4helpr;
  Ipv4InterfaceContainer hostIpIfaces;
  ipv4helpr.SetBase ("10.1.1.0", "255.255.255.0");
  hostIpIfaces = ipv4helpr.Assign (hostDevices);

  if (loadfile2 != "none")
    {
      ReadDemands (T, loadfile2, rateUnit, factor, true);
      FilterDemands (T, minHops);
    }
  if (shuffle2)
    {
      ShuffleDemands (T, shuffle2);
    }

  // Configure OnOff applications between hosts
  Config::SetDefault ("ns3::TcpSocket::SegmentSize", UintegerValue (payloadSize));

  OnOffHelper onoff ("ns3::TcpSocketFactory", Ipv4Address::GetAny ());
  onoff.SetAttribute ("OnTime", StringValue ("ns3::UniformRandomVariable[Min=" + std::to_string (onTime/2) + "|Max=" + std::to_string (onTime*1.5) + "]"));
  onoff.SetAttribute ("OffTime", StringValue ("ns3::UniformRandomVariable[Max=" + std::to_string (offTime/2) + "|Max=" + std::to_string (offTime*1.5) + "]"));
  onoff.SetAttribute ("PacketSize", UintegerValue (payloadSize));

  std::map<std::pair<uint16_t,uint16_t>,ApplicationContainer> senderApps;
  std::map<std::pair<uint16_t,uint16_t>,ApplicationContainer> sinkApps;

  // add numFlowsPerDemand sender and sink apps for each demand
  uint16_t dstPort = 4000;

  for (auto& d : T.m_demands)
    {
      // Null demands may be added just to create the DAG in the opposite direction (for TCP acks)
      if (d.second == 0.)
        {
          continue;
        }

      for (uint16_t i = 0; i < numFlowsPerDemand; i++)
        {
          // receiver side
          PacketSinkHelper packetSinkHelper ("ns3::TcpSocketFactory",
                                             InetSocketAddress (Ipv4Address::GetAny (), dstPort += 7));
          sinkApps[d.first].Add (packetSinkHelper.Install (hosts.Get (d.first.second)));

          // sender side
//           double frac = 2. * (i+1) / (numFlowsPerDemand * (numFlowsPerDemand+1));  // the sum over all i is 1
          double frac = ((i % 10) + 1.) / (numFlowsPerDemand / 2. * (numFlowsPerDemand / 10. + 1.));
          double surplus = (onTime + offTime) / onTime;
          onoff.SetAttribute ("DataRate", DataRateValue (d.second * frac * surplus));
          onoff.SetAttribute ("Remote", AddressValue (InetSocketAddress (hostIpIfaces.GetAddress (d.first.second), dstPort)));
          senderApps[d.first].Add (onoff.Install (hosts.Get (d.first.first)));
        }

//         V4PingHelper pingHelper = V4PingHelper (hostIpIfaces.GetAddress (d.first.second));
//         pingHelper.SetAttribute ("Verbose", BooleanValue (true));
//         senderApps[d.first].Add (pingHelper.Install (hosts.Get (d.first.first)));

        senderApps[d.first].Start (Seconds (start));
        senderApps[d.first].Stop (Seconds (start + duration));

        sinkApps[d.first].Start (Seconds (start - 1.));
        sinkApps[d.first].Stop (Seconds (start + duration));
    }

  // Enable datapath stats and pcap traces at hosts, switch(es), and controller(s)
  //    of13Helper->EnableDatapathStats ("switch-stats");
  if (trace)
    {
      of13Helper->EnableOpenFlowPcap ("openflow");
      for (uint16_t i = 0; i < T.m_nodes.size (); i++)
        {
          csmaHelper.EnablePcap ("switch", switchPorts[i], true);
        }
      csmaHelper.EnablePcap ("host", hostDevices);
      of13Helper->EnableDatapathLogs ();
      of13Helper->EnableDatapathStats ("switch-stats");
    }

  // Enable flow monitor
  FlowMonitorHelper flowmon;
  Ptr<FlowMonitor> monitor = flowmon.InstallAll();
  monitor->Start (Seconds (start + warmup));
//   Simulator::Schedule (Seconds (start + duration - warmup), &FlowMonitor::StopRightNow, monitor); 

  for (double t = warmup; t <= duration; t++)
    {
      for (auto& u : linkUtil)
        {
          Simulator::Schedule (Seconds (start + t), &MeasureUtil::ResetInterval, u);
        }
    }

  if (duration < warmup)
    {
      std::cout << std::endl << "*** Duration should be higher than warmup ***" << std::endl;
    }

  // Run the simulation
  Simulator::Stop (Seconds (start + duration));
  Simulator::Run ();
  Simulator::Destroy ();

  std::cout << std::endl << "**** Application statistics ****" << std::endl;
  std::cout << left << std::setw (10) << "Demand"
            << right << std::setw (12) << "TX (Mbps)"
                     << std::setw (12) << "RX (Mbps)"
                     << std::setw (10) << "%" << std::endl;

  for (auto& d : T.m_demands)
    {
      // Null demands may be added just to create the DAG in the opposite direction (for TCP acks)
      if (d.second == 0.)
        {
          continue;
        }

      uint64_t rxBytes = 0;

      for (auto app = sinkApps[d.first].Begin (); app != sinkApps[d.first].End (); app++)
        {
          rxBytes += DynamicCast<PacketSink> (*app)->GetTotalRx ();
        }

      std::cout << left << std::setw (10) << "(" << d.first.first << "," << d.first.second << ")"
                << right << std::setw (12) << d.second / 1000000.0
                         << std::setw (12) << rxBytes * 8.0 / (duration * 1000000.0)
                         << std::setw (12) << rxBytes * 8.0 / (duration * d.second) << std::endl;
    }

  std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats ();
  Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier> (flowmon.GetClassifier ());

  std::map<std::pair<uint16_t,uint16_t>,MyStats> demstats;

  std::cout << std::endl << "**** Flow monitor statistics ****" << std::endl;
  std::cout << left << std::setw (10) << "Demand"
            << right << std::setw (12) << "TX (Mbps)"
                     << std::setw (12) << "RX (Mbps)"
                     << std::setw (12) << "%"
                     << std::setw (12) << "Delay (ms)"
                     << std::setw (12) << "Drop QD"
                     << std::setw (12) << "Drop ND" << std::endl;

  for (auto& flow : stats)
    {
      auto tuple = classifier->FindFlow (flow.first);
      uint8_t addr[4];

      tuple.sourceAddress.Serialize (addr);
      if (addr[0] != 10 || addr[1] != 1 || addr[2] != 1)
        {
	      continue;
        }
      uint16_t src = addr[3]-1;

      tuple.destinationAddress.Serialize (addr);
      if (addr[0] != 10 || addr[1] != 1 || addr[2] != 1)
        {
	      continue;
        }
      uint16_t dst = addr[3]-1;

      double load = 0;
//       double txInterval = flow.second.timeLastTxPacket.GetSeconds ()
//                           - flow.second.timeFirstTxPacket.GetSeconds ();
//       if (txInterval)
//         {
          load = flow.second.txBytes * 8.0 / (duration-warmup) / 1000000;
//         }

      double throughput = 0;
//       double rxInterval = flow.second.timeLastRxPacket.GetSeconds ()
//                           - flow.second.timeFirstRxPacket.GetSeconds ();
//       if (rxInterval)
//       {
        throughput = flow.second.rxBytes * 8.0 / (duration-warmup) / 1000000;
//       }

      uint32_t dropQD = 0;
      if (flow.second.packetsDropped.size () > Ipv4FlowProbe::DROP_QUEUE_DISC)
        {
          dropQD = flow.second.packetsDropped[Ipv4FlowProbe::DROP_QUEUE_DISC];
        }

      uint32_t dropND = 0;
      if (flow.second.packetsDropped.size () > Ipv4FlowProbe::DROP_QUEUE)
        {
          dropND = flow.second.packetsDropped[Ipv4FlowProbe::DROP_QUEUE];
        }

      if (demstats.find ({src, dst}) == demstats.end ())
        {
          demstats[{src, dst}].m_load = load;
          demstats[{src, dst}].m_throughput = throughput;
          demstats[{src, dst}].m_delaySum = flow.second.delaySum.GetMilliSeconds ();
          demstats[{src, dst}].m_rxPackets = flow.second.rxPackets;
          demstats[{src, dst}].m_dropQD = dropQD;
          demstats[{src, dst}].m_dropND = dropND;
        }
      else
        {
          demstats[{src, dst}].m_load += load;
          demstats[{src, dst}].m_throughput += throughput;
          demstats[{src, dst}].m_delaySum += flow.second.delaySum.GetMilliSeconds ();
          demstats[{src, dst}].m_rxPackets += flow.second.rxPackets;
          demstats[{src, dst}].m_dropQD += dropQD;
          demstats[{src, dst}].m_dropND += dropND;
        }
    }

  std::stringstream suffix;
  suffix << topofile.substr (topofile.find_last_of ('/')+1) << "_h" << minHops << "_f" << factor
         << "_b" << bins;
  if (loadfile != "none")
    {
        suffix << "_l" << loadfile.substr (loadfile.size ()-6, 2);
    }
  if (loadfile2 != "none")
    {
        suffix << "_ld" << loadfile2.substr (loadfile2.size ()-6, 2);
    }
  if (shuffle)
    {
      suffix << "_s" << shuffle;
    }
  if (shuffle2)
    {
      suffix << "_ss" << shuffle2;
    }
  ofstream ftput ("tput_" + suffix.str ());
  ofstream ftputTot ("tputTot_" + suffix.str ());
  ofstream fdelay ("delay_" + suffix.str ());
  ofstream futil ("util_" + suffix.str ());
  double tputTot = 0.;

  for (auto& dem : demstats)
    {
      std::cout << left << std::setw (10) << "(" << dem.first.first << "," << dem.first.second << ")"
                << right << std::setw (12) << dem.second.m_load
                         << std::setw (12) << dem.second.m_throughput
             << std::setw (12) << dem.second.m_throughput / dem.second.m_load
             << std::setw (12) << (dem.second.m_rxPackets ? dem.second.m_delaySum / dem.second.m_rxPackets : 0)
             << std::setw (12) << dem.second.m_dropQD
             << std::setw (12) << dem.second.m_dropND << std::endl;

      tputTot += dem.second.m_throughput;

      ftput << dem.second.m_throughput << std::endl;
      if (dem.second.m_rxPackets)
        {
          fdelay << dem.second.m_delaySum / dem.second.m_rxPackets << std::endl;
        }

      if (T.m_demands.find (dem.first) == T.m_demands.end ())
      {
        std::cout << "The demand above is unknown" << std::endl;
      }
    }

  ftputTot << tputTot << std::endl;

  for (auto& u : linkUtil)
    {
      u->Print (futil);
      delete u;
    }

  ftput.close ();
  ftputTot.close ();
  fdelay.close ();
  futil.close ();
}



// Read topology
void ReadTopology (Topology& T, std::string topofile, std::string rateUnit, double factor, bool verbose)
{
  std::string s, t;
  uint16_t u, v;
  double d, cap;

  std::ifstream f (topofile);

  if (!f.is_open ())
    {
      std::cout << "Failed to open " << topofile << std::endl;
      exit (0);
    }

  // Search for token NODES
  f >> s;
  while (s != "NODES")
    {
      if (f.eof () || f.bad ())
        {
          std::cout << "NODES token not found" << std::endl;
          exit (0);
        }
      f.ignore(std::numeric_limits<std::streamsize>::max(), '\n');  // ignore the line
      f >> s;
    }

  f >> s;   // get '('

  // Read node names
  f >> s;
  while (s != ")")
    {
      if (f.eof () || f.bad ())
        {
          std::cout << "Error while reading nodes" << std::endl;
          exit (0);
        }
      if (verbose)
        {
          std::cout << "Found node labelled " << s << std::endl;
        }
      T.m_nodes.push_back (s);
      f.ignore(std::numeric_limits<std::streamsize>::max(), '\n');  // ignore the rest of the line
      f >> s;
    }

  // Search for token LINKS
  f >> s;
  while (s != "LINKS")
    {
      if (f.eof () || f.bad ())
        {
          std::cout << "LINKS token not found" << std::endl;
          exit (0);
        }
      f.ignore(std::numeric_limits<std::streamsize>::max(), '\n');  // ignore the line
      f >> s;
    }

  f >> s;   // get '('

  // Read links
  while (s != ")")
    {
      f.ignore(std::numeric_limits<std::streamsize>::max(), '(');  // ignore chars until '('
      f >> s >> t;
      if (f.eof () || f.bad ())
        {
          std::cout << "Error while reading links" << std::endl;
          exit (0);
        }

      auto i = std::find (T.m_nodes.begin (), T.m_nodes.end (), s);
      if (i == T.m_nodes.end ())
        {
          std::cout << "Node " << s << " not found" << std::endl;
          exit (0);
        }
      u = std::distance (T.m_nodes.begin (), i);

      i = std::find (T.m_nodes.begin (), T.m_nodes.end (), t);
      if (i == T.m_nodes.end ())
        {
          std::cout << "Node " << t << " not found" << std::endl;
          exit (0);
        }
      v = std::distance (T.m_nodes.begin (), i);

      if (verbose)
        {
          std::cout << "Found link between " << u << "(" << s << ") and " << v << "(" << t << ") ";
        }

      f >> s;   // get ')'
      getline (f, s);
      stringstream ss(s);

      ss >> cap >> d >> d >> d;   // read pre_installed capacity and skip the other three values
      ss >> s;                    // skip '('
      while (ss >> d)
        {
          cap += d;
          ss >> d;               // skip module_cost
        }

      if (verbose)
        {
          std::cout << "capacity " << cap << std::endl;
        }

      T.m_links.insert ({{u,v},cap});
      f >> s;
    }

  f.close ();
  ReadDemands (T, topofile, rateUnit, factor, verbose);
}

void ReadDemands (Topology& T, std::string topofile, std::string rateUnit, double factor, bool verbose)
{
  std::string s, t;
  uint16_t u, v;
  double d;

  std::ifstream f (topofile);

  if (!f.is_open ())
    {
      std::cout << "Failed to open " << topofile << std::endl;
      exit (0);
    }

  T.m_demands.clear ();

  // Search for token DEMANDS
  f >> s;
  while (s != "DEMANDS")
    {
      if (f.eof () || f.bad ())
        {
          std::cout << "DEMANDS token not found" << std::endl;
          exit (0);
        }
      f.ignore(std::numeric_limits<std::streamsize>::max(), '\n');  // ignore the line
      f >> s;
    }

  f >> t>> s;   // get '('

  // Read demands
  while (s != ")")
    {
      f >> s;                // skip '('
      if (f.eof () || f.bad ())
        {
          std::cout << "Error while reading demands" << std::endl;
          exit (0);
        }

      f >> s >> t;

      auto i = std::find (T.m_nodes.begin (), T.m_nodes.end (), s);
      if (i == T.m_nodes.end ())
        {
          std::cout << "Node " << s << " not found" << std::endl;
          exit (0);
        }
      u = std::distance (T.m_nodes.begin (), i);

      i = std::find (T.m_nodes.begin (), T.m_nodes.end (), t);
      if (i == T.m_nodes.end ())
        {
          std::cout << "Node " << t << " not found" << std::endl;
          exit (0);
        }
      v = std::distance (T.m_nodes.begin (), i);

      if (verbose)
        {
          std::cout << "Found demand between " << u << "(" << s << ") and " << v << "(" << t << ") ";
        }

      f >> s >> t;   // get ')' and routing_unit
      f >> s;
      stringstream ss(s);

      ss >> d;       // read demand_value
      f >> s;        // skip max_path_length

      d *= factor;   // apply multiplicative factor

      if (verbose)
        {
          std::cout << "value " << d << rateUnit << std::endl;
        }

      DataRate bwd (std::to_string (d) + rateUnit);
      if (d > 0.1)
        {
          T.m_demands.insert ({{u,v}, bwd.GetBitRate ()});
        }
      f >> s;
    }

  f.close ();
}


void FilterDemands (Topology& T, uint16_t minHops)
{
  Linklist ll;
  for (auto& l : T.m_links)
    {
      ll.push_back (l.first);
      ll.push_back ({l.first.second,l.first.first});
    }
  SubGraph g(ll);

  DijkstraShortestPathAlg dijkstra (&g);

  for (auto d = T.m_demands.begin (); d != T.m_demands.end (); )
    {
      dijkstra.get_shortest_path(g.get_vertex(d->first.first), NULL);

      if (dijkstra.get_start_distance_at (g.get_vertex(d->first.second)) < minHops)
        {
          std::cout << "Discarding demand between " << d->first.first << " and " << d->first.second
                    << " (distance: " << dijkstra.get_start_distance_at (g.get_vertex(d->first.second)) << ")"
                    << std::endl;
          auto tmp = d++;
          T.m_demands.erase (tmp);
        }
      else
        {
          std::cout << "Leaving demand between " << d->first.first << " and " << d->first.second
                    << " (distance: " << dijkstra.get_start_distance_at (g.get_vertex(d->first.second)) << ")"
                    << std::endl;
          d++;
        }
    }

  // Add null demands to ensure all demands are bidirectional
  for (auto d = T.m_demands.begin (); d != T.m_demands.end (); d++)
    {
      auto it = T.m_demands.find ({d->first.second,d->first.first});

      if (it == T.m_demands.end ())
        {
          std::cout << "Adding null demand between " << d->first.second << " and " << d->first.first << std::endl;
          T.m_demands.insert ({{d->first.second,d->first.first},0.});
        }
    }

  std::cout << "Remaining demands " << T.m_demands.size () << std::endl;
}


void ShuffleDemands (Topology& T, uint16_t shuffle)
{
  std::cout << "Shuffling demands..." << std::endl;

  auto begin = T.m_demands.begin();
  for (uint16_t i=0; i < T.m_demands.size () / (2*shuffle); i++)
    {
      auto next = begin;
      for (auto j=0; j<shuffle; j++)
        {
          next++;
        }

      for (auto j=0; j<shuffle; j++)
        {
          double temp = begin->second;
          begin->second = next->second;
          next->second = temp;
          begin++;
          next++;
        }

      begin = next;
    }
  std::cout << "Done" << std::endl;
}
