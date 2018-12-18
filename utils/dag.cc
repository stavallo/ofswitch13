#include "dag.h"
#include <limits>

namespace ns3 {

void DAG::addLinks (std::set<std::pair<int,int> > links)
{
  for (std::set<std::pair<int,int> >::iterator l = links.begin(); l != links.end(); l++)
  {
    nodes.at(l->first).added = true;
    nodes.at(l->second).added = true;
    nodes[l->first].adj.insert(l->second);
  }
}

void DAG::removeLink(int u, int v)
{
  nodes.at(u).adj.erase(v);
}

void DAG::removeNode(int u)
{
  for (uint16_t i=0; i<nodes.size(); i++)
    if (i == u) {
      nodes[i].adj.clear();
      nodes[i].added = false;
    }
    else
      nodes[i].adj.erase(u);
}


void DAG::DAGelem::Print(std::ostream& os) const
{
  os << "Adj: ";
  for (std::set<int>::const_iterator v=adj.begin(); v!=adj.end(); v++)
    os << *v << " ";
  os << "\t  max_dist_to_dest: " << max_dist_to_dest << std::endl;
}

void DAG::Print(std::ostream& os) const
{
  if (acyclic)
    os << "The graph is acyclic" << std::endl;
  if (sortedDAG.empty()) {
    for (std::vector<DAGelem>::const_iterator u=nodes.begin(); u!=nodes.end(); u++)
      if (u->added) {
	os << distance(nodes.begin(), u) << ": ";
	u->Print(os);
      }
  } else {
    os << "In sorted order:" << std::endl;
    for (std::list<int>::const_iterator u=sortedDAG.begin(); u!=sortedDAG.end(); u++) {
	os << *u << ": pred(" << nodes[*u].pred << ") ";
	nodes[*u].Print(os);
      }
  }

  os << std::endl;
}

std::ostream & operator << (std::ostream &os, const DAG &dag)
{
  dag.Print (os);
  return os;
}


void DAG::DFS(int s)
{
  acyclic = true;
  sortedDAG.clear();
  for (std::vector<DAGelem>::iterator u=nodes.begin(); u!=nodes.end(); u++) {
    u->color = DAGelem::white;
    u->pred = numNodes;
  }
  time = 0;
  DFS_Visit(s);
}

void DAG::DFS_Visit(int u)
{
  nodes.at(u).color = DAGelem::gray;
  nodes.at(u).time_d = ++time;
  
  for (std::set<int>::iterator v=nodes[u].adj.begin(); v!=nodes[u].adj.end(); v++)
    if (nodes.at(*v).color == DAGelem::white) {
      nodes[*v].pred = u;
      DFS_Visit(*v);
    }
    else if (nodes.at(*v).color == DAGelem::gray)   // BACK EDGE !
      acyclic = false;
    
  nodes[u].color = DAGelem::black;
  nodes[u].time_f = ++time;

  if (sortedDAG.empty())
    nodes[u].max_dist_to_dest = 0;   // this is the last node in the topological ordering
  else {
    nodes[u].max_dist_to_dest = 0;
    for (std::set<int>::iterator v=nodes[u].adj.begin(); v!=nodes[u].adj.end(); v++)
      if (nodes[*v].max_dist_to_dest > nodes[u].max_dist_to_dest - 1)
	nodes[u].max_dist_to_dest = nodes[*v].max_dist_to_dest + 1;
  }
    
  sortedDAG.push_front(u);
}


int DAG::getMaxDistToDest(int u)
{
  return nodes.at(u).max_dist_to_dest;
}


int DAG::getMaxDistFromSource(int n)
{
  if (sortedDAG.empty()) {
    std::cerr << "DAG not sorted! getMaxDistromSource quits" << std::endl;
    return -1;
  }

  // reset pred and time_d (used as distance)
  for (std::vector<DAGelem>::iterator u=nodes.begin(); u!=nodes.end(); u++) {
    u->time_d = std::numeric_limits<int>::max();
    u->pred = numNodes;
  }

  // the source node is the first one in the topological order
  nodes[sortedDAG.front()].time_d = 0;

  for (std::list<int>::iterator u=sortedDAG.begin(); u!=sortedDAG.end(); u++)
    for (std::set<int>::iterator v=nodes[*u].adj.begin(); v!=nodes[*u].adj.end(); v++)
      // the weight of a link is -1
      if (nodes[*v].time_d > nodes[*u].time_d - 1) {
	nodes[*v].time_d = nodes[*u].time_d - 1;
	nodes[*v].pred = *u;
      }

  return -nodes.at(n).time_d;
}

} // namespace ns3
