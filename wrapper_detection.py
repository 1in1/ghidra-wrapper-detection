from Queue import Queue

from ghidra.program.util import CyclomaticComplexity
from cyclotomic import computeAllComplexities

def computeComplexities(fnIt):
    cc = CyclomaticComplexity()
    return { f: cc.calculateCyclomaticComplexity(f, monitor) for f in fnIt }

def vertexRemovalSeparatesGraph(f, g):
    # We search through the graph from g to determine if we can reach any of the values in H
    # Perform a simple BFS
    H = set(f.getCallingFunctions(None))
    visited = set()
    q = Queue()
    q.put(g)
    while not q.empty():
        nextNode = q.get()
        if nextNode in H:
            return False
        visited.add(nextNode)
        map(q.put, filter(lambda h: h not in visited, nextNode.getCallingFunctions(None)))
    return True

def getPotentialWrappers(g, complexityTolerance = 3):
    potentialWrappers = filter(lambda f: vertexRemovalSeparatesGraph(f, g), g.getCallingFunctions(None))
    complexities = computeComplexities(potentialWrappers)
    return filter(lambda f: complexities[f], potentialWrappers)

if __name__ == "__main__":
    fm = currentProgram.getFunctionManager()

    for g in fm.getFunctions(True):
        print("Potential wrappers of {0}".format(g.getSignature().getPrototypeString())) 
        print(getPotentialWrappers(g))

