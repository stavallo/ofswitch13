#ifndef WMN_DAG
#define WMN_DAG

#include <vector>
#include <list>
#include <set>
#include <iostream>

namespace ns3 {

class DAG {

private:
  
class DAGelem {
public:
  enum Color {
    white = 0,
    gray,    
    black
  };
  
  bool added;
  std::set<int> adj;
  enum Color color;
  int pred;
  int time_d;
  int time_f;
  int max_dist_to_dest;

  // constructor
  DAGelem () : added(false) {}

  void Print (std::ostream& os) const;
};


public:
  // constructor
  DAG (int _numNodes) : numNodes(_numNodes), acyclic(true) { nodes.resize(_numNodes); }

  // add links of the given path to the dag
  void addLinks (std::set<std::pair<int,int> > links);

  // remove the link from u to v
  void removeLink (int u, int v);

  // remove node u and all of its links
  void removeNode (int u);

  /*
   * Makes a Depth-First-Search on the dag (starting from the source s)
   * Sets acyclic and fills sortedDAG
   */ 
  void DFS (int s);

  bool isAcyclic() { return acyclic; }

  void Print (std::ostream& os) const;

  std::list<int>::const_iterator sorted_begin ()    { return sortedDAG.begin(); }
  std::list<int>::const_iterator sorted_end ()      { return sortedDAG.end(); }

  std::list<int>::const_reverse_iterator sorted_rbegin ()    { return sortedDAG.rbegin(); }
  std::list<int>::const_reverse_iterator sorted_rend ()      { return sortedDAG.rend(); }

  std::set<int>::const_iterator adj_begin (int u)    { return nodes.at(u).adj.begin(); }
  std::set<int>::const_iterator adj_end (int u)      { return nodes.at(u).adj.end(); }

  int getPred (int u)  { return nodes.at(u).pred; }

  int getNumNodes ()   { return numNodes; }

  // requires that DFS has been called
  // the destination is the last node in the topological order
  int getMaxDistToDest (int u);

  // requires that DFS has been called
  // the source is the first node in the topological order
  // changes pred and time_d, but NOT sortedDAG
  int getMaxDistFromSource (int u);
  
  int getNumAdj (int u) { return nodes.at(u).adj.size(); }

private:
  
  void DFS_Visit(int u);
  
  int numNodes;
  std::vector<DAGelem> nodes;

  std::list<int> sortedDAG;         // the list of nodes in topological ordering (filled by DFS)

  int time;                    // used by DFS
  bool acyclic;
};

/**
 * \brief Stream insertion operator.
 *
 * \param os the stream
 * \param item the item
 * \returns a reference to the stream
 */
std::ostream& operator<< (std::ostream& os, const DAG &dag);

} // namespace ns3

#endif
