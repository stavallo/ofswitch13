#include "subgraph.h"

namespace ns3 {

SubGraph::SubGraph(const AdjLists& T, bool reversed)
: Graph(".WMemptygraph")
//   m_reversed (reversed)
{
  clear();

  m_nVertexNum = T.size ();

  // create all the vertices (NEEDED in case some nodes have no links)
  for (int i = 0; i < m_nVertexNum; i++)
    {
      get_vertex (i);
    }

  for (uint64_t u=0; u < T.size (); u++)
    for (auto v=T[u].begin (); v!=T[u].end (); v++) {
      // construct the vertices
      BaseVertex* start_vertex_pt = reversed ? get_vertex(*v) : get_vertex(u);
      BaseVertex* end_vertex_pt = reversed ? get_vertex(u) : get_vertex(*v);

      // add the edge weight (1 for now)
      m_mpEdgeCodeWeight[get_edge_code(start_vertex_pt, end_vertex_pt)] = 1;

      // update the fan-in or fan-out variables
      // Fan-in
      get_vertex_set_pt(end_vertex_pt, m_mpFaninVertices)->insert(start_vertex_pt);

      // Fan-out
      get_vertex_set_pt(start_vertex_pt, m_mpFanoutVertices)->insert(end_vertex_pt);
  }

  m_nVertexNum = m_vtVertices.size();
  m_nEdgeNum = m_mpEdgeCodeWeight.size();
}


SubGraph::SubGraph(const Linklist& L, bool reversed)
: Graph(".WMemptygraph")
//   m_reversed (reversed)
{
  clear();

  uint16_t m = 0;
  for (auto& l : L)
    {
      if (l.first > m)
        m = l.first;
      if (l.second > m)
        m = l.second;
    }

  m_nVertexNum = m + 1;

  // create all the vertices (NEEDED in case some nodes have no links)
  for (int i = 0; i < m_nVertexNum; i++)
    {
      get_vertex (i);
    }

  for (auto& l : L)
    {
      // construct the vertices
      BaseVertex* start_vertex_pt = reversed ? get_vertex(l.second) : get_vertex(l.first);
      BaseVertex* end_vertex_pt = reversed ? get_vertex(l.first) : get_vertex(l.second);

      // add the edge weight (1 for now)
      m_mpEdgeCodeWeight[get_edge_code(start_vertex_pt, end_vertex_pt)] = 1;

      // update the fan-in or fan-out variables
      // Fan-in
      get_vertex_set_pt(end_vertex_pt, m_mpFaninVertices)->insert(start_vertex_pt);

      // Fan-out
      get_vertex_set_pt(start_vertex_pt, m_mpFanoutVertices)->insert(end_vertex_pt);
    }

  m_nVertexNum = m_vtVertices.size();
  m_nEdgeNum = m_mpEdgeCodeWeight.size();
}


SubGraph::SubGraph(const SubGraph& graph) : Graph(graph)
{
  for (BaseVertexPt2SetMapIterator i=m_mpFaninVertices.begin(); i!=m_mpFaninVertices.end(); i++)
    i->second = new set<BaseVertex*>(*(i->second));

  for (BaseVertexPt2SetMapIterator i=m_mpFanoutVertices.begin(); i!=m_mpFanoutVertices.end(); i++)
    i->second = new set<BaseVertex*>(*(i->second));

  m_stRemovedEdge.clear();
  m_stRemovedVertexIds.clear();
}


SubGraph::~SubGraph()
{
  m_mpFanoutVertices.clear();
  m_mpFaninVertices.clear();
  m_vtVertices.clear();
  m_mpVertexIndex.clear();
}


void SubGraph::removeEdge(int u, int v) {
  m_mpEdgeCodeWeight.erase(get_edge_code(get_vertex(u),get_vertex(v)));
  get_vertex_set_pt(get_vertex(v), m_mpFaninVertices)->erase(get_vertex(u));
  get_vertex_set_pt(get_vertex(u), m_mpFanoutVertices)->erase(get_vertex(v));
  
  m_nEdgeNum = m_mpEdgeCodeWeight.size();
}


void SubGraph::removeVertex(int u)
{
  // remove incoming edges
  BaseVertexPt2SetMapIterator pos = m_mpFaninVertices.find(get_vertex(u));
  
  if (pos != m_mpFaninVertices.end()) {
    for (set<BaseVertex*>::iterator v=pos->second->begin(); v!=pos->second->end(); v++)
      m_mpEdgeCodeWeight.erase(get_edge_code(*v,get_vertex(u)));
    pos->second->clear();
  }
  
  // remove outgoing edges
  pos = m_mpFanoutVertices.find(get_vertex(u));
  
  if (pos != m_mpFanoutVertices.end()) {
    for (set<BaseVertex*>::iterator v=pos->second->begin(); v!=pos->second->end(); v++)
      m_mpEdgeCodeWeight.erase(get_edge_code(get_vertex(u),*v));
    pos->second->clear();
  }

  m_nEdgeNum = m_mpEdgeCodeWeight.size();
}

#if 0
void SubGraph::pruneEdges (linkPruneFunc* prune)
{
  if (!prune)
    return;

  for (TGraphNodeIterator u = m_topology->NodeBegin(); u != m_topology->NodeEnd(); u++)
    for (TGraphNeighborIterator v = u->NeighborBegin(); v != u->NeighborEnd(); v++)
      if ((*prune)(m_topology->LinkItrs(u,v)))
      {
	int start = m_reversed ? v->Id() : u->Id();
	int end = m_reversed ? u->Id() : v->Id();
	removeEdge (start, end);
      }
}
#endif

void SubGraph::pruneEdges (std::function<bool(uint16_t,uint16_t)> f)
{
  std::list<std::pair<uint16_t,uint16_t>> toBeRemoved;

  for (uint16_t u = 0; u < m_nVertexNum; u++)
    {
      set<BaseVertex*>* vertex_pt_set = get_vertex_set_pt (get_vertex (u), m_mpFanoutVertices);

      for (const auto& v : (*vertex_pt_set))
        {
          if (f (u,v->getID ()))
            {
              toBeRemoved.push_back ({u, v->getID ()});
            }
        }
    }

  for (auto& l : toBeRemoved)
    {
      removeEdge (l.first, l.second);
    }
}

void SubGraph::setLinkCosts (std::function<double(uint16_t,uint16_t)> f)
{
  for (uint16_t u = 0; u < m_nVertexNum; u++)
    {
      set<BaseVertex*>* vertex_pt_set = get_vertex_set_pt (get_vertex (u), m_mpFanoutVertices);

      for (const auto& v : (*vertex_pt_set))
        {
          m_mpEdgeCodeWeight[get_edge_code(get_vertex (u), v)] = f (u,v->getID());
        }
    }
}


std::ostream & operator << (std::ostream &os, const BasePath *path)
{
  path->PrintOut (os);
  return os;
}

} // namespace ns3
