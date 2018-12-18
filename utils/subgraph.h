#ifndef SUB_GRAPH
#define SUB_GRAPH

#include <vector>
#include <set>
#include <map>
#include <list>
#include <fstream>
#include <functional>
#include <ksp/GraphElements.h>
#include <ksp/Graph.h>

namespace ns3 {

typedef std::vector<std::list<uint64_t>> AdjLists;
typedef std::vector<std::pair<uint16_t,uint16_t>> Linklist;
/*
 * This class is just defined to create an empty file to pass to the Graph constructor,
 * before the Graph constructor is called
 */
class EmptyGraph
{
public:
  EmptyGraph () { m_ofs.open (".WMemptygraph", ofstream::out); m_ofs.close (); }
private:
  ofstream m_ofs;
};

/*
 * SubGraph is a class derived from Graph (ksp_2.0) to add:
 * - a constructor to build a graph from an AdjLists
 * - methods to remove an edge or a vertex from a graph
 * - a (more) correct copy constructor
 * - a (more) correct destructor
 */
class SubGraph : public EmptyGraph, public Graph {
public:
  /*
   * Construct a Subgraph starting from adjacency lists. This
   * constructor does NOT add the inverse link, i.e., if B is
   * in A's neighbor list, a link A->B is created but a link
   * B->A is not created. Node IDs start at 0.
   */
  SubGraph(const AdjLists& T, bool reversed = false);

  /*
   * Construct a Subgraph starting from a list of links. This
   * constructor does NOT add the inverse link, i.e., if a link
   * A->B is in the list, a link A->B is created but a link
   * B->A is not created. Node IDs start at 0.
   */
  SubGraph(const Linklist& L, bool reversed = false);

  SubGraph (const SubGraph& graph);

  ~SubGraph ();

  void removeEdge (int u, int v);

  void removeVertex (int u);

  int getNumVertices (void) { return m_nVertexNum; }

  void pruneEdges (std::function<bool(uint16_t,uint16_t)> f);

  void setLinkCosts (std::function<double(uint16_t,uint16_t)> f);

// private:
//   bool m_reversed;
};

/**
 * \brief Stream insertion operator.
 *
 * \param os the stream
 * \param item the item
 * \returns a reference to the stream
 */
std::ostream& operator<< (std::ostream& os, const BasePath *path);

} // namespace ns3

#endif
