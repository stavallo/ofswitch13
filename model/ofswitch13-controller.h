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

#ifndef OFSWITCH13_CONTROLLER_H
#define OFSWITCH13_CONTROLLER_H

#include "ns3/application.h"
#include "ofswitch13-interface.h"
#include "ofswitch13-net-device.h"

namespace ns3 {

class OFSwitch13NetDevice;

/**
 * \ingroup ofswitch13
 *
 * \brief An ofs::Controller interface for OFSwitch13NetDevices OpenFlow 1.3
 * switch NetDevice
 *
 * This controller should manage the OpenFlow 1.3 datapath. It does not need to
 * be full-compliant with the protocol specification. 
 */
class OFSwitch13Controller : public Application
{
public:
  OFSwitch13Controller ();
  virtual ~OFSwitch13Controller ();

  // inherited from Object
  static TypeId GetTypeId (void);
  virtual void DoDispose ();
 
  /**
   * Register a switch to this controller.
   *
   * \param swtch The Ptr<OFSwitch13NetDevice> switch to register.
   */
  virtual void AddSwitch (Ptr<OFSwitch13NetDevice> swtch);

  /**
   * \brief Create a flow_mod message using the same syntax from dpctl, and
   * send it to the switch.
   *
   * \param swtch The Ptr<OFSwitch13NetDevice> switch to register.
   * \param textCmd The dpctl flow_mod command to create the message.
   */
  void SendFlowModMsg (Ptr<OFSwitch13NetDevice> sw, const char* textCmd);

   /**
   * \brief A registered switch can call this method to send a message to this
   * Controller.
   *
   * \param swtch The switch the message was received from.
   * \param buffer The pointer to the buffer containing the message.
   */
  virtual void ReceiveFromSwitch (Ptr<OFSwitch13NetDevice> swtch, ofpbuf* buffer);

protected:
  /**
   * \brief This method is used to send a message to a registered switch. It
   * will encapsulate the ofl_msg format into an ofpbuf wire format.
   *
   * \param swtch The switch to receive the message.
   * \param msg The message to send.
   */
  void SendToSwitch (Ptr<OFSwitch13NetDevice> swtch, void *msg);

  /**
   * \internal
   *
   * Get the packet type on the buffer, which can then be used
   * to determine how to handle the buffer.
   *
   * \param buffer The packet in OpenFlow buffer format.
   * \return The packet type, as defined in the ofp_type struct.
   */
  uint8_t GetPacketType (ofpbuf* buffer);

  typedef std::set<Ptr<OFSwitch13NetDevice> > Switches_t;
  Switches_t m_switches;  ///< The collection of switches registered to this controller.

private:
  static const uint32_t m_global_xid = 0xf0ff00f0;  ///!< Global ID (same from dpctl)

  // inherited from Application
  virtual void StartApplication (void);
  virtual void StopApplication (void);


//void ParseFlowModArgs (char *str, struct ofl_msg_flow_mod *req);



};

} // namespace ns3
#endif /* OFSWITCH13_CONTROLLER_H */
