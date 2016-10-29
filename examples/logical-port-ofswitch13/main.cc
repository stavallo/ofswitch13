/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2016 University of Campinas (Unicamp)
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
 *
 * Two hosts connected through two OpenFlow switches, both managed by the
 * tunnel controller. Traffic between the switches are encapsulated with GTP
 * protocol, to illustrate how logical ports can be used on OpenFlow switches.
 * TCP traffic flows from host 0 to host 1.
 *
 *                         Tunnel Controller
 *                                 |
 *                       +-------------------+
 *                       |                   |
 *                  +----------+       +----------+
 *       Host 0 === | Switch 0 | OOOOO | Switch 1 | === Host 1
 *                  +----------+       +----------+
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/ofswitch13-module.h"
#include "tunnel.h"

using namespace ns3;

int
main (int argc, char *argv[])
{
  bool verbose = false;
  bool trace = false;
  uint16_t simTime = 30;

  // Configure command line parameters
  CommandLine cmd;
  cmd.AddValue ("verbose", "Enable verbose output", verbose);
  cmd.AddValue ("trace", "Enable pcap trace files output", trace);
  cmd.AddValue ("simTime", "Simulation time", simTime);
  cmd.Parse (argc, argv);

  if (verbose)
    {
      LogComponentEnable ("OFSwitch13Interface", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Helper", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Device", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Port", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Controller", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13LearningController", LOG_LEVEL_ALL);
    }

  // Enabling Checksum computations
  GlobalValue::Bind ("ChecksumEnabled", BooleanValue (true));

  // Creating two host nodes
  NodeContainer hosts;
  hosts.Create (2);

  // Create the two switch nodes
  NodeContainer switches;
  switches.Create (2);

  // Create the controller node
  Ptr<Node> controllerNode = CreateObject<Node> ();

  // Starting the OpenFlow network configuration
  Ptr<OFSwitch13Helper> of13Helper = CreateObject<OFSwitch13Helper> ();
  Ptr<TunnelController> ofController = CreateObject<TunnelController> ();
  of13Helper->InstallController (controllerNode, ofController);
  OFSwitch13DeviceContainer ofDevices = of13Helper->InstallSwitch (switches);
  Ptr<OFSwitch13Device> sw0 = ofDevices.Get (0);
  Ptr<OFSwitch13Device> sw1 = ofDevices.Get (1);

  // Use the CsmaHelper to connect the host nodes to the switch.
  CsmaHelper csmaHelper;
  csmaHelper.SetChannelAttribute ("DataRate", DataRateValue (DataRate ("100Mbps")));
  csmaHelper.SetChannelAttribute ("Delay", TimeValue (MilliSeconds (2)));

  NodeContainer pair;
  NetDeviceContainer pairDevs;
  NetDeviceContainer hostDevices;

  // Connect host 0 to first switch
  pair = NodeContainer (hosts.Get (0), switches.Get (0));
  pairDevs = csmaHelper.Install (pair);
  hostDevices.Add (pairDevs.Get (0));
  sw0->AddSwitchPort (pairDevs.Get (1));

  // Connect host 1 to second switch
  pair = NodeContainer (hosts.Get (1), switches.Get (1));
  pairDevs = csmaHelper.Install (pair);
  hostDevices.Add (pairDevs.Get (0));
  sw1->AddSwitchPort (pairDevs.Get (1));

  // Connect the switches
  pair = NodeContainer (switches.Get (0), switches.Get (1));
  pairDevs = csmaHelper.Install (pair);

  // Configure theses ports as logical ports, to de/encapsulate traffic
  TunnelHandler *tunnel = new TunnelHandler ();
  sw0->AddSwitchPort (pairDevs.Get (0),
                      MakeCallback (&TunnelHandler::Receive, tunnel),
                      MakeCallback (&TunnelHandler::Send, tunnel));
  sw1->AddSwitchPort (pairDevs.Get (1),
                      MakeCallback (&TunnelHandler::Receive, tunnel),
                      MakeCallback (&TunnelHandler::Send, tunnel));

  // Finalizing the OpenFlow network configuration
  of13Helper->CreateOpenFlowChannels ();

  // Install the TCP/IP stack into hosts
  InternetStackHelper internet;
  internet.Install (hosts);

  // Set IPv4 terminal address
  Ipv4AddressHelper ipv4switches;
  Ipv4InterfaceContainer internetIpIfaces;
  ipv4switches.SetBase ("10.1.1.0", "255.255.255.0");
  internetIpIfaces = ipv4switches.Assign (hostDevices);

  // Send TCP traffic from host 0 to 1
  Ipv4Address dstAddr = internetIpIfaces.GetAddress (1);
  BulkSendHelper senderHelper ("ns3::TcpSocketFactory", InetSocketAddress (dstAddr, 9));
  senderHelper.Install (hosts.Get (0));
  PacketSinkHelper sinkHelper ("ns3::TcpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), 9));
  ApplicationContainer sinkApp = sinkHelper.Install (hosts.Get (1));

  // Enable datapath logs
  if (verbose)
    {
      of13Helper->EnableDatapathLogs ("all");
    }

  // Enable pcap traces
  if (trace)
    {
      of13Helper->EnableOpenFlowPcap ();
      csmaHelper.EnablePcap ("ofswitch", switches, true);
      csmaHelper.EnablePcap ("host", hostDevices);
    }

  // Run the simulation
  Simulator::Stop (Seconds (simTime));
  Simulator::Run ();
  Simulator::Destroy ();

  // Print transmitted bytes
  Ptr<PacketSink> sink = DynamicCast<PacketSink> (sinkApp.Get (0));
  std::cout << "Total bytes sent from host 0 to host 1: " << sink->GetTotalRx () << std::endl;

  delete tunnel;
}