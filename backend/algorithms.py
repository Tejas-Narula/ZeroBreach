
from collections import deque


def find_reachable_devices(graph, start_device):
    if start_device not in graph:
        raise ValueError(f"Device '{start_device}' does not exist")

    visited = {start_device}
    queue = deque([start_device])

    while queue:
        current = queue.popleft()

        for neighbor in graph.successors(current):
            edge_data = graph[current][neighbor]

            if not edge_data.get("allowed", False):
                continue

            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(neighbor)

    return visited
